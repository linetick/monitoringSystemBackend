import importlib.util
import sys
import types
import unittest
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


def make_user_query(result):
    query = mock.Mock()
    query.filter.return_value = query
    query.first.return_value = result
    return query


class Day6SourceRegressionTests(unittest.TestCase):
    def test_user_management_routes_are_admin_only_and_audited(self):
        main_source = read_source("app/main.py")

        self.assertIn('@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)', main_source)
        self.assertIn('@app.get("/users", response_model=List[UserResponse])', main_source)
        self.assertIn('@app.put("/users/{user_id}", response_model=UserResponse)', main_source)
        self.assertIn('@app.delete("/users/{user_id}")', main_source)
        self.assertIn("current_user: models.User = Depends(get_current_admin_user)", main_source)
        self.assertIn('"CREATE_USER"', main_source)
        self.assertIn('"UPDATE_USER"', main_source)
        self.assertIn('"DELETE_USER"', main_source)

    def test_user_safety_checks_and_helpers_exist(self):
        main_source = read_source("app/main.py")

        self.assertIn('raise HTTPException(status_code=400, detail="Username already registered")', main_source)
        self.assertIn('raise HTTPException(status_code=400, detail="Cannot delete yourself")', main_source)
        self.assertIn('raise HTTPException(status_code=400, detail="Cannot remove your own admin role")', main_source)
        self.assertIn('raise HTTPException(status_code=400, detail="Cannot deactivate yourself")', main_source)
        self.assertIn('raise HTTPException(status_code=400, detail="No changes provided")', main_source)
        self.assertIn("def ensure_username_available(", main_source)
        self.assertIn("def get_user_or_404(", main_source)
        self.assertIn("def build_user_audit_details(", main_source)


class UserManagementHelperTests(unittest.TestCase):
    @staticmethod
    def _load_main_module():
        fastapi_module = types.ModuleType("fastapi")
        fastapi_module.Depends = lambda dependency=None: dependency
        fastapi_module.FastAPI = FakeFastAPI
        fastapi_module.HTTPException = FakeHTTPException
        fastapi_module.Query = lambda default=None, **kwargs: default
        fastapi_module.Request = object
        fastapi_module.Response = object
        fastapi_module.status = types.SimpleNamespace(
            HTTP_201_CREATED=201,
            HTTP_400_BAD_REQUEST=400,
            HTTP_401_UNAUTHORIZED=401,
            HTTP_403_FORBIDDEN=403,
            HTTP_404_NOT_FOUND=404,
        )

        fastapi_encoders_module = types.ModuleType("fastapi.encoders")
        fastapi_encoders_module.jsonable_encoder = lambda value: value

        fastapi_responses_module = types.ModuleType("fastapi.responses")
        fastapi_responses_module.StreamingResponse = object

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
        auth_module.verify_password = mock.Mock(return_value=True)
        auth_module.get_password_hash = mock.Mock(side_effect=lambda password: f"hashed::{password}")
        auth_module.create_access_token = mock.Mock(return_value="signed-token")
        auth_module.settings = types.SimpleNamespace(access_token_expire_minutes=30)

        database_module = types.ModuleType("app.database")
        database_module.get_db = lambda: None

        class FakeUserModel:
            id = "id"
            username = "username"

            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class FakeAuditLogModel:
            username = "username"
            action = "action"
            object_name = "object_name"
            ip_address = "ip_address"
            timestamp = "timestamp"
            user_id = "user_id"

        models_module = types.ModuleType("app.models")
        models_module.User = FakeUserModel
        models_module.AuditLog = FakeAuditLogModel

        system_module = types.ModuleType("app.system")
        system_module.get_server_metrics = mock.Mock()
        system_module.get_processes = mock.Mock(return_value=([], 0))
        system_module.manage_process = mock.Mock()

        audit_module = types.ModuleType("app.audit")
        audit_module.create_audit_entry = mock.Mock()
        audit_module.create_user_audit_entry = mock.Mock()

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
            f"app.test_day6_main_{id(auth_module)}",
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
        return module, auth_module, audit_module, models_module, roles_module

    def test_get_user_or_404_returns_user_or_raises(self):
        main_module, _, _, _, _ = self._load_main_module()

        db = mock.Mock()
        db.query.return_value.filter.return_value.first.return_value = types.SimpleNamespace(id=7)
        result = main_module.get_user_or_404(db, 7)
        self.assertEqual(result.id, 7)

        db.query.return_value.filter.return_value.first.return_value = None
        with self.assertRaises(FakeHTTPException) as context:
            main_module.get_user_or_404(db, 999)

        self.assertEqual(context.exception.status_code, 404)
        self.assertEqual(context.exception.detail, "User not found")

    def test_ensure_username_available_rejects_duplicates_and_supports_exclude_id(self):
        main_module, _, _, _, _ = self._load_main_module()

        duplicate_db = mock.Mock()
        duplicate_db.query.return_value.filter.return_value.first.return_value = types.SimpleNamespace(id=1)
        with self.assertRaises(FakeHTTPException) as duplicate_context:
            main_module.ensure_username_available(duplicate_db, "alice")

        self.assertEqual(duplicate_context.exception.status_code, 400)
        self.assertEqual(duplicate_context.exception.detail, "Username already registered")

        available_db = mock.Mock()
        query = mock.Mock()
        query.filter.return_value = query
        query.first.return_value = None
        available_db.query.return_value = query

        main_module.ensure_username_available(available_db, "alice", exclude_user_id=5)

        self.assertEqual(query.filter.call_count, 2)

    def test_build_user_audit_details_is_stable(self):
        main_module, _, _, _, _ = self._load_main_module()
        user = types.SimpleNamespace(username="alice", role="admin", is_active=False)

        self.assertEqual(
            main_module.build_user_audit_details(user),
            "username=alice; role=admin; is_active=False",
        )


class UserCrudEndpointTests(unittest.TestCase):
    @staticmethod
    def _load_main_module():
        return UserManagementHelperTests._load_main_module()

    def test_create_user_hashes_password_persists_user_and_audits(self):
        main_module, auth_module, audit_module, models_module, roles_module = self._load_main_module()
        db = mock.Mock()
        user_query = make_user_query(None)
        db.query.return_value = user_query
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        admin_user = types.SimpleNamespace(id=1, username="admin", role="admin")
        user_data = types.SimpleNamespace(
            username="alice",
            password="secret123",
            is_active=False,
            role=roles_module.UserRole.ADMIN,
        )

        result = main_module.create_user(
            user=user_data,
            request=request,
            db=db,
            current_user=admin_user,
        )

        created_user = db.add.call_args.args[0]
        self.assertIsInstance(created_user, models_module.User)
        self.assertEqual(created_user.username, "alice")
        self.assertEqual(created_user.hashed_password, "hashed::secret123")
        self.assertEqual(created_user.is_active, False)
        self.assertEqual(created_user.role, "admin")
        self.assertIs(result, created_user)
        auth_module.get_password_hash.assert_called_once_with("secret123")
        db.commit.assert_called_once_with()
        db.refresh.assert_called_once_with(created_user)
        audit_module.create_user_audit_entry.assert_called_once_with(
            db,
            user=admin_user,
            action="CREATE_USER",
            object_name="alice",
            ip_address="127.0.0.1",
            details="username=alice; role=admin; is_active=False",
        )

    def test_read_users_returns_paginated_query_result(self):
        main_module, _, _, models_module, _ = self._load_main_module()
        db = mock.Mock()
        expected_users = [types.SimpleNamespace(id=1), types.SimpleNamespace(id=2)]
        db.query.return_value.offset.return_value.limit.return_value.all.return_value = expected_users

        result = main_module.read_users(
            skip=5,
            limit=10,
            current_user=types.SimpleNamespace(id=1, username="admin"),
            db=db,
        )

        self.assertIs(result, expected_users)
        db.query.assert_called_once_with(models_module.User)
        db.query.return_value.offset.assert_called_once_with(5)
        db.query.return_value.offset.return_value.limit.assert_called_once_with(10)

    def test_update_user_applies_all_supported_changes_and_audits(self):
        main_module, auth_module, audit_module, _, roles_module = self._load_main_module()
        db = mock.Mock()
        db_user = types.SimpleNamespace(
            id=2,
            username="old-name",
            hashed_password="old-hash",
            role="limited",
            is_active=False,
        )
        lookup_query = make_user_query(db_user)
        availability_query = make_user_query(None)
        db.query.side_effect = [lookup_query, availability_query]
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        admin_user = types.SimpleNamespace(id=1, username="admin", role="admin")
        update_data = types.SimpleNamespace(
            username="new-name",
            password="new-secret",
            role=roles_module.UserRole.ADMIN,
            is_active=True,
        )

        result = main_module.update_user(
            user_id=2,
            user_update=update_data,
            request=request,
            db=db,
            current_user=admin_user,
        )

        self.assertIs(result, db_user)
        self.assertEqual(db_user.username, "new-name")
        self.assertEqual(db_user.hashed_password, "hashed::new-secret")
        self.assertEqual(db_user.role, "admin")
        self.assertTrue(db_user.is_active)
        auth_module.get_password_hash.assert_called_once_with("new-secret")
        db.commit.assert_called_once_with()
        db.refresh.assert_called_once_with(db_user)
        audit_module.create_user_audit_entry.assert_called_once_with(
            db,
            user=admin_user,
            action="UPDATE_USER",
            object_name="new-name",
            ip_address="127.0.0.1",
            details="username=new-name; password=updated; role=admin; is_active=True",
        )

    def test_update_user_rejects_empty_payload(self):
        main_module, auth_module, audit_module, _, _ = self._load_main_module()
        db = mock.Mock()
        db.query.return_value = make_user_query(
            types.SimpleNamespace(
                id=2,
                username="alice",
                hashed_password="old-hash",
                role="admin",
                is_active=True,
            )
        )
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))

        with self.assertRaises(FakeHTTPException) as context:
            main_module.update_user(
                user_id=2,
                user_update=types.SimpleNamespace(
                    username=None,
                    password=None,
                    role=None,
                    is_active=None,
                ),
                request=request,
                db=db,
                current_user=types.SimpleNamespace(id=1, username="admin", role="admin"),
            )

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "No changes provided")
        auth_module.get_password_hash.assert_not_called()
        db.commit.assert_not_called()
        audit_module.create_user_audit_entry.assert_not_called()

    def test_update_user_prevents_self_demotion_and_self_deactivation(self):
        main_module, _, audit_module, _, roles_module = self._load_main_module()

        db_demote = mock.Mock()
        db_demote.query.return_value = make_user_query(
            types.SimpleNamespace(
                id=10,
                username="admin",
                hashed_password="hash",
                role="admin",
                is_active=True,
            )
        )
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        admin_user = types.SimpleNamespace(id=10, username="admin", role="admin")

        with self.assertRaises(FakeHTTPException) as demote_context:
            main_module.update_user(
                user_id=10,
                user_update=types.SimpleNamespace(
                    username=None,
                    password=None,
                    role=roles_module.UserRole.LIMITED,
                    is_active=None,
                ),
                request=request,
                db=db_demote,
                current_user=admin_user,
            )

        self.assertEqual(demote_context.exception.status_code, 400)
        self.assertEqual(demote_context.exception.detail, "Cannot remove your own admin role")
        audit_module.create_user_audit_entry.assert_not_called()

        db_deactivate = mock.Mock()
        db_deactivate.query.return_value = make_user_query(
            types.SimpleNamespace(
                id=10,
                username="admin",
                hashed_password="hash",
                role="admin",
                is_active=True,
            )
        )

        with self.assertRaises(FakeHTTPException) as deactivate_context:
            main_module.update_user(
                user_id=10,
                user_update=types.SimpleNamespace(
                    username=None,
                    password=None,
                    role=None,
                    is_active=False,
                ),
                request=request,
                db=db_deactivate,
                current_user=admin_user,
            )

        self.assertEqual(deactivate_context.exception.status_code, 400)
        self.assertEqual(deactivate_context.exception.detail, "Cannot deactivate yourself")

    def test_delete_user_rejects_self_delete(self):
        main_module, _, audit_module, _, _ = self._load_main_module()
        db = mock.Mock()
        db.query.return_value = make_user_query(
            types.SimpleNamespace(
                id=5,
                username="admin",
                role="admin",
                is_active=True,
            )
        )
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        admin_user = types.SimpleNamespace(id=5, username="admin", role="admin")

        with self.assertRaises(FakeHTTPException) as context:
            main_module.delete_user(
                user_id=5,
                request=request,
                db=db,
                current_user=admin_user,
            )

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "Cannot delete yourself")
        db.delete.assert_not_called()
        audit_module.create_user_audit_entry.assert_not_called()

    def test_delete_user_detaches_audit_logs_and_audits_deletion(self):
        main_module, _, audit_module, models_module, _ = self._load_main_module()
        db = mock.Mock()
        user_to_delete = types.SimpleNamespace(
            id=7,
            username="alice",
            role="limited",
            is_active=False,
        )
        user_query = make_user_query(user_to_delete)
        audit_query = mock.Mock()
        audit_query.filter.return_value = audit_query
        db.query.side_effect = [user_query, audit_query]
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        admin_user = types.SimpleNamespace(id=1, username="admin", role="admin")

        result = main_module.delete_user(
            user_id=7,
            request=request,
            db=db,
            current_user=admin_user,
        )

        self.assertEqual(result, {"status": "success"})
        audit_query.update.assert_called_once_with(
            {models_module.AuditLog.user_id: None},
            synchronize_session=False,
        )
        db.delete.assert_called_once_with(user_to_delete)
        db.commit.assert_called_once_with()
        audit_module.create_user_audit_entry.assert_called_once_with(
            db,
            user=admin_user,
            action="DELETE_USER",
            object_name="alice",
            ip_address="127.0.0.1",
            details="username=alice; role=limited; is_active=False",
        )


if __name__ == "__main__":
    unittest.main()
