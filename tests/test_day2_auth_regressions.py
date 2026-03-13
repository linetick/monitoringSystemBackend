import asyncio
import importlib.util
import sys
import types
import unittest
import warnings
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def read_source(relative_path: str) -> str:
    return (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")


def load_module_from_path(module_name: str, relative_path: str, injected_modules=None):
    injected_modules = injected_modules or {}
    saved_modules = {name: sys.modules.get(name) for name in injected_modules}

    for name, module in injected_modules.items():
        sys.modules[name] = module

    spec = importlib.util.spec_from_file_location(module_name, PROJECT_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    loader = spec.loader
    if loader is None:
        raise RuntimeError(f"Unable to load module from {relative_path}")

    try:
        loader.exec_module(module)
        return module
    finally:
        sys.modules.pop(module_name, None)
        for name, original_module in saved_modules.items():
            if original_module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original_module


class FakeHTTPException(Exception):
    def __init__(self, status_code, detail, headers=None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.headers = headers or {}


class FakeFastAPI:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def _decorator(self, *args, **kwargs):
        def wrap(function):
            return function

        return wrap

    get = _decorator
    post = _decorator
    put = _decorator
    delete = _decorator


class Day2SourceRegressionTests(unittest.TestCase):
    def test_auth_related_routes_and_audit_markers_exist(self):
        main_source = read_source("app/main.py")
        dependency_source = read_source("app/dependencies.py")

        self.assertIn('@app.post("/token"', main_source)
        self.assertIn('@app.get("/users/me"', main_source)
        self.assertIn('action="LOGIN_FAILED"', main_source)
        self.assertIn('"LOGIN_SUCCESS"', main_source)
        self.assertIn('action="FORBIDDEN_ADMIN_ACCESS"', dependency_source)
        self.assertIn('detail="Could not validate credentials"', dependency_source)
        self.assertIn('"WWW-Authenticate": "Bearer"', dependency_source)


class AuthModuleTests(unittest.TestCase):
    @staticmethod
    def _load_auth_module(secret_key):
        jose_module = types.ModuleType("jose")
        jose_module.jwt = mock.Mock()

        passlib_module = types.ModuleType("passlib")
        passlib_context_module = types.ModuleType("passlib.context")

        class FakeCryptContext:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

            def verify(self, plain_password, hashed_password):
                return plain_password == hashed_password

            def hash(self, password):
                return f"hashed::{password}"

        passlib_context_module.CryptContext = FakeCryptContext

        app_package = types.ModuleType("app")
        app_package.__path__ = []

        config_module = types.ModuleType("app.config")
        config_module.settings = types.SimpleNamespace(
            secret_key=secret_key,
            algorithm="HS512",
            access_token_expire_minutes=45,
        )

        return load_module_from_path(
            f"app.test_day2_auth_{secret_key or 'missing'}",
            "app/auth.py",
            {
                "jose": jose_module,
                "passlib": passlib_module,
                "passlib.context": passlib_context_module,
                "app": app_package,
                "app.config": config_module,
            },
        ), jose_module.jwt

    def test_get_secret_key_requires_env_value(self):
        auth_module, _ = self._load_auth_module(secret_key=None)

        with self.assertRaisesRegex(RuntimeError, "SECRET_KEY environment variable is required"):
            auth_module.get_secret_key()

    def test_create_access_token_uses_configured_secret_and_algorithm(self):
        auth_module, jwt_mock = self._load_auth_module(secret_key="super-secret")
        jwt_mock.encode.return_value = "signed.jwt"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            token = auth_module.create_access_token({"sub": "alice"})

        self.assertEqual(token, "signed.jwt")
        self.assertEqual(jwt_mock.encode.call_args.kwargs["algorithm"], "HS512")
        self.assertEqual(jwt_mock.encode.call_args.args[1], "super-secret")
        self.assertEqual(jwt_mock.encode.call_args.args[0]["sub"], "alice")
        self.assertIn("exp", jwt_mock.encode.call_args.args[0])


class DependencyTests(unittest.TestCase):
    @staticmethod
    def _load_dependencies_module(decode_mock, safe_create_audit_entry_mock):
        fastapi_module = types.ModuleType("fastapi")
        fastapi_module.Depends = lambda dependency=None: dependency
        fastapi_module.HTTPException = FakeHTTPException
        fastapi_module.Request = object
        fastapi_module.status = types.SimpleNamespace(
            HTTP_401_UNAUTHORIZED=401,
            HTTP_403_FORBIDDEN=403,
        )

        fastapi_security_module = types.ModuleType("fastapi.security")
        fastapi_security_module.OAuth2PasswordBearer = lambda tokenUrl: tokenUrl

        jose_module = types.ModuleType("jose")

        class FakeJWTError(Exception):
            pass

        jose_module.JWTError = FakeJWTError
        jose_module.jwt = types.SimpleNamespace(decode=decode_mock)

        sqlalchemy_module = types.ModuleType("sqlalchemy")
        sqlalchemy_orm_module = types.ModuleType("sqlalchemy.orm")
        sqlalchemy_orm_module.Session = object

        app_package = types.ModuleType("app")
        app_package.__path__ = []

        auth_module = types.ModuleType("app.auth")
        auth_module.get_secret_key = mock.Mock(return_value="secret-key")
        auth_module.settings = types.SimpleNamespace(algorithm="HS256")

        database_module = types.ModuleType("app.database")
        database_module.get_db = lambda: None

        class FakeUserModel:
            username = "username"

        models_module = types.ModuleType("app.models")
        models_module.User = FakeUserModel

        audit_module = types.ModuleType("app.audit")
        audit_module.safe_create_audit_entry = safe_create_audit_entry_mock

        roles_module = types.ModuleType("app.roles")
        roles_module.UserRole = types.SimpleNamespace(
            ADMIN=types.SimpleNamespace(value="admin")
        )

        module = load_module_from_path(
            f"app.test_day2_dependencies_{id(decode_mock)}",
            "app/dependencies.py",
            {
                "fastapi": fastapi_module,
                "fastapi.security": fastapi_security_module,
                "jose": jose_module,
                "sqlalchemy": sqlalchemy_module,
                "sqlalchemy.orm": sqlalchemy_orm_module,
                "app": app_package,
                "app.auth": auth_module,
                "app.database": database_module,
                "app.models": models_module,
                "app.audit": audit_module,
                "app.roles": roles_module,
            },
        )
        return module, FakeJWTError, auth_module

    def test_get_current_user_returns_401_for_invalid_token(self):
        decode_mock = mock.Mock()
        safe_create_audit_entry_mock = mock.Mock()
        dependencies_module, fake_jwt_error, auth_module = self._load_dependencies_module(
            decode_mock,
            safe_create_audit_entry_mock,
        )
        decode_mock.side_effect = fake_jwt_error("bad-token")
        db = mock.Mock()

        with self.assertRaises(FakeHTTPException) as context:
            asyncio.run(dependencies_module.get_current_user(token="bad", db=db))

        self.assertEqual(context.exception.status_code, 401)
        self.assertEqual(context.exception.detail, "Could not validate credentials")
        self.assertEqual(context.exception.headers, {"WWW-Authenticate": "Bearer"})
        auth_module.get_secret_key.assert_called_once()

    def test_get_current_user_rejects_inactive_user(self):
        decode_mock = mock.Mock(return_value={"sub": "alice"})
        safe_create_audit_entry_mock = mock.Mock()
        dependencies_module, _, _ = self._load_dependencies_module(
            decode_mock,
            safe_create_audit_entry_mock,
        )

        user = types.SimpleNamespace(id=1, username="alice", is_active=False, role="limited")
        db = mock.Mock()
        db.query.return_value.filter.return_value.first.return_value = user

        with self.assertRaises(FakeHTTPException) as context:
            asyncio.run(dependencies_module.get_current_user(token="good", db=db))

        self.assertEqual(context.exception.status_code, 403)
        self.assertEqual(context.exception.detail, "Inactive user")

    def test_get_current_admin_user_logs_forbidden_access_for_limited_user(self):
        decode_mock = mock.Mock(return_value={"sub": "limited-user"})
        safe_create_audit_entry_mock = mock.Mock()
        dependencies_module, _, _ = self._load_dependencies_module(
            decode_mock,
            safe_create_audit_entry_mock,
        )

        limited_user = types.SimpleNamespace(id=3, username="limited-user", role="limited")
        request = types.SimpleNamespace(
            url=types.SimpleNamespace(path="/users"),
            method="GET",
            client=types.SimpleNamespace(host="127.0.0.1"),
        )
        db = mock.Mock()

        with self.assertRaises(FakeHTTPException) as context:
            asyncio.run(
                dependencies_module.get_current_admin_user(
                    request=request,
                    db=db,
                    current_user=limited_user,
                )
            )

        self.assertEqual(context.exception.status_code, 403)
        self.assertEqual(
            context.exception.detail,
            "Not enough permissions. Admin access required.",
        )
        safe_create_audit_entry_mock.assert_called_once_with(
            db,
            action="FORBIDDEN_ADMIN_ACCESS",
            object_name="/users",
            ip_address="127.0.0.1",
            username="limited-user",
            user_id=3,
            details="method=GET",
        )

    def test_get_current_admin_user_returns_admin_without_audit(self):
        decode_mock = mock.Mock(return_value={"sub": "admin"})
        safe_create_audit_entry_mock = mock.Mock()
        dependencies_module, _, _ = self._load_dependencies_module(
            decode_mock,
            safe_create_audit_entry_mock,
        )

        admin_user = types.SimpleNamespace(id=1, username="admin", role="admin")
        request = types.SimpleNamespace(
            url=types.SimpleNamespace(path="/users"),
            method="GET",
            client=types.SimpleNamespace(host="127.0.0.1"),
        )
        db = mock.Mock()

        result = asyncio.run(
            dependencies_module.get_current_admin_user(
                request=request,
                db=db,
                current_user=admin_user,
            )
        )

        self.assertIs(result, admin_user)
        safe_create_audit_entry_mock.assert_not_called()


class LoginFlowTests(unittest.TestCase):
    @staticmethod
    def _load_main_module(create_audit_entry_mock, create_user_audit_entry_mock, verify_password_result):
        fastapi_module = types.ModuleType("fastapi")
        fastapi_module.Depends = lambda dependency=None: dependency
        fastapi_module.FastAPI = FakeFastAPI
        fastapi_module.HTTPException = FakeHTTPException
        fastapi_module.Query = lambda default=None, **kwargs: default
        fastapi_module.Request = object
        fastapi_module.Response = object
        fastapi_module.status = types.SimpleNamespace(
            HTTP_201_CREATED=201,
            HTTP_401_UNAUTHORIZED=401,
            HTTP_403_FORBIDDEN=403,
        )

        fastapi_encoders_module = types.ModuleType("fastapi.encoders")
        fastapi_encoders_module.jsonable_encoder = lambda value: value

        fastapi_responses_module = types.ModuleType("fastapi.responses")

        class FakeStreamingResponse:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs

        fastapi_responses_module.StreamingResponse = FakeStreamingResponse

        fastapi_security_module = types.ModuleType("fastapi.security")

        class FakeOAuth2PasswordRequestForm:
            def __init__(self, username="", password=""):
                self.username = username
                self.password = password

        fastapi_security_module.OAuth2PasswordRequestForm = FakeOAuth2PasswordRequestForm

        sqlalchemy_module = types.ModuleType("sqlalchemy")
        sqlalchemy_orm_module = types.ModuleType("sqlalchemy.orm")
        sqlalchemy_orm_module.Session = object

        app_package = types.ModuleType("app")
        app_package.__path__ = []

        auth_module = types.ModuleType("app.auth")
        auth_module.verify_password = mock.Mock(return_value=verify_password_result)
        auth_module.get_password_hash = mock.Mock(side_effect=lambda password: f"hashed::{password}")
        auth_module.create_access_token = mock.Mock(return_value="signed-token")
        auth_module.settings = types.SimpleNamespace(access_token_expire_minutes=30)

        database_module = types.ModuleType("app.database")
        database_module.get_db = lambda: None

        class FakeUserModel:
            username = "username"
            id = "id"

        class FakeAuditLogModel:
            username = "username"
            action = "action"
            object_name = "object_name"
            ip_address = "ip_address"
            timestamp = "timestamp"

        models_module = types.ModuleType("app.models")
        models_module.User = FakeUserModel
        models_module.AuditLog = FakeAuditLogModel

        system_module = types.ModuleType("app.system")
        system_module.get_server_metrics = mock.Mock()
        system_module.get_processes = mock.Mock(return_value=([], 0))
        system_module.manage_process = mock.Mock()

        audit_module = types.ModuleType("app.audit")
        audit_module.create_audit_entry = create_audit_entry_mock
        audit_module.create_user_audit_entry = create_user_audit_entry_mock

        roles_module = types.ModuleType("app.roles")
        roles_module.UserRole = types.SimpleNamespace(
            ADMIN=types.SimpleNamespace(value="admin"),
            LIMITED=types.SimpleNamespace(value="limited"),
        )

        config_module = types.ModuleType("app.config")
        config_module.settings = types.SimpleNamespace(
            processes_default_limit=100,
            processes_max_limit=500,
        )

        def placeholder(name):
            return type(name, (), {})

        schemas_module = types.ModuleType("app.schemas")
        for name in [
            "AuditLogResponse",
            "ProcessAction",
            "ProcessActionResult",
            "ProcessInfo",
            "ServerMetrics",
            "Token",
            "UserCreate",
            "UserResponse",
            "UserUpdate",
        ]:
            setattr(schemas_module, name, placeholder(name))
        schemas_module.ProcessSortField = types.SimpleNamespace(
            PID=types.SimpleNamespace(value="pid")
        )
        schemas_module.SortDirection = types.SimpleNamespace(
            ASC=types.SimpleNamespace(value="asc")
        )

        dependencies_module = types.ModuleType("app.dependencies")
        dependencies_module.get_current_user = lambda: None
        dependencies_module.get_current_admin_user = lambda: None

        module = load_module_from_path(
            f"app.test_day2_main_{id(create_audit_entry_mock)}",
            "app/main.py",
            {
                "fastapi": fastapi_module,
                "fastapi.encoders": fastapi_encoders_module,
                "fastapi.responses": fastapi_responses_module,
                "fastapi.security": fastapi_security_module,
                "sqlalchemy": sqlalchemy_module,
                "sqlalchemy.orm": sqlalchemy_orm_module,
                "app": app_package,
                "app.auth": auth_module,
                "app.database": database_module,
                "app.models": models_module,
                "app.system": system_module,
                "app.audit": audit_module,
                "app.roles": roles_module,
                "app.config": config_module,
                "app.schemas": schemas_module,
                "app.dependencies": dependencies_module,
            },
        )
        return module, auth_module

    def test_login_success_returns_token_and_audits_login(self):
        create_audit_entry_mock = mock.Mock()
        create_user_audit_entry_mock = mock.Mock()
        main_module, auth_module = self._load_main_module(
            create_audit_entry_mock,
            create_user_audit_entry_mock,
            verify_password_result=True,
        )

        user = types.SimpleNamespace(id=1, username="alice", hashed_password="stored", is_active=True)
        db = mock.Mock()
        db.query.return_value.filter.return_value.first.return_value = user
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        form_data = types.SimpleNamespace(username="alice", password="stored")

        result = main_module.login(request=request, form_data=form_data, db=db)

        self.assertEqual(result, {"access_token": "signed-token", "token_type": "bearer"})
        auth_module.create_access_token.assert_called_once()
        create_audit_entry_mock.assert_not_called()
        create_user_audit_entry_mock.assert_called_once_with(
            db,
            user=user,
            action="LOGIN_SUCCESS",
            object_name="/token",
            ip_address="127.0.0.1",
            details="token_type=bearer",
        )

    def test_login_invalid_credentials_returns_401_and_audits_failure(self):
        create_audit_entry_mock = mock.Mock()
        create_user_audit_entry_mock = mock.Mock()
        main_module, _ = self._load_main_module(
            create_audit_entry_mock,
            create_user_audit_entry_mock,
            verify_password_result=False,
        )

        user = types.SimpleNamespace(id=1, username="alice", hashed_password="stored", is_active=True)
        db = mock.Mock()
        db.query.return_value.filter.return_value.first.return_value = user
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        form_data = types.SimpleNamespace(username="alice", password="wrong-password")

        with self.assertRaises(FakeHTTPException) as context:
            main_module.login(request=request, form_data=form_data, db=db)

        self.assertEqual(context.exception.status_code, 401)
        self.assertEqual(context.exception.detail, "Incorrect username or password")
        self.assertEqual(context.exception.headers, {"WWW-Authenticate": "Bearer"})
        create_audit_entry_mock.assert_called_once_with(
            db,
            action="LOGIN_FAILED",
            object_name="/token",
            ip_address="127.0.0.1",
            username="alice",
            details="reason=invalid_credentials",
        )
        create_user_audit_entry_mock.assert_not_called()

    def test_login_inactive_user_returns_403_and_audits_failure(self):
        create_audit_entry_mock = mock.Mock()
        create_user_audit_entry_mock = mock.Mock()
        main_module, _ = self._load_main_module(
            create_audit_entry_mock,
            create_user_audit_entry_mock,
            verify_password_result=True,
        )

        user = types.SimpleNamespace(id=7, username="alice", hashed_password="stored", is_active=False)
        db = mock.Mock()
        db.query.return_value.filter.return_value.first.return_value = user
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        form_data = types.SimpleNamespace(username="alice", password="stored")

        with self.assertRaises(FakeHTTPException) as context:
            main_module.login(request=request, form_data=form_data, db=db)

        self.assertEqual(context.exception.status_code, 403)
        self.assertEqual(context.exception.detail, "Inactive user")
        create_audit_entry_mock.assert_called_once_with(
            db,
            action="LOGIN_FAILED",
            object_name="/token",
            ip_address="127.0.0.1",
            username="alice",
            user_id=7,
            details="reason=inactive_user",
        )
        create_user_audit_entry_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
