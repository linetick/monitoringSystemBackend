import importlib.util
import json
import sys
import types
import unittest
from datetime import datetime, timezone
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


class FakeStreamingResponse:
    def __init__(self, content, media_type=None, headers=None):
        self.content = content
        self.media_type = media_type
        self.headers = headers or {}
        if hasattr(content, "getvalue"):
            self.body = content.getvalue()
        elif hasattr(content, "read"):
            self.body = content.read()
        else:
            self.body = content


class FakeColumn:
    def __init__(self, name):
        self.name = name

    def ilike(self, pattern):
        return f"{self.name} ILIKE {pattern}"

    def __ge__(self, value):
        return (self.name, ">=", value)

    def __le__(self, value):
        return (self.name, "<=", value)

    def desc(self):
        return f"{self.name} DESC"


class FakeQuery:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.filters = []
        self.order_by_value = None
        self.limit_value = None

    def filter(self, expression):
        self.filters.append(expression)
        return self

    def order_by(self, expression):
        self.order_by_value = expression
        return self

    def limit(self, value):
        self.limit_value = value
        return self

    def all(self):
        return self.rows


class Day7SourceRegressionTests(unittest.TestCase):
    def test_audit_routes_support_filters_limits_and_export_formats(self):
        main_source = read_source("app/main.py")

        self.assertIn('@app.get("/audit", response_model=List[AuditLogResponse])', main_source)
        self.assertIn('@app.get("/audit/export")', main_source)
        self.assertIn('@app.post("/logout")', main_source)
        self.assertIn('limit: int = Query(100, ge=1, le=1000)', main_source)
        self.assertIn('limit: int = Query(1000, ge=1, le=5000)', main_source)
        self.assertIn('format: str = Query("csv", regex="^(csv|json)$")', main_source)
        self.assertIn('return StreamingResponse(', main_source)
        self.assertIn('media_type="application/json"', main_source)
        self.assertIn('media_type="text/csv"', main_source)

    def test_audit_markers_cover_login_users_processes_and_forbidden_admin_access(self):
        main_source = read_source("app/main.py")
        dependency_source = read_source("app/dependencies.py")

        self.assertIn('"LOGIN_SUCCESS"', main_source)
        self.assertIn('action="LOGIN_FAILED"', main_source)
        self.assertIn('"LOGOUT"', main_source)
        self.assertIn('"CREATE_USER"', main_source)
        self.assertIn('"UPDATE_USER"', main_source)
        self.assertIn('"DELETE_USER"', main_source)
        self.assertIn('"PROCESS_CONTROL"', main_source)
        self.assertIn('"PROCESS_CONTROL_FAILED"', main_source)
        self.assertIn('action="FORBIDDEN_ADMIN_ACCESS"', dependency_source)
        self.assertIn('"AUDIT_VIEW"', main_source)
        self.assertIn('"AUDIT_EXPORT"', main_source)


class AuditHelpersTests(unittest.TestCase):
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
            HTTP_401_UNAUTHORIZED=401,
            HTTP_403_FORBIDDEN=403,
        )

        jsonable_encoder_mock = mock.Mock(side_effect=lambda value: value)
        fastapi_encoders_module = types.ModuleType("fastapi.encoders")
        fastapi_encoders_module.jsonable_encoder = jsonable_encoder_mock

        fastapi_responses_module = types.ModuleType("fastapi.responses")
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
        auth_module.verify_password = mock.Mock(return_value=True)
        auth_module.get_password_hash = mock.Mock(side_effect=lambda password: f"hashed::{password}")
        auth_module.create_access_token = mock.Mock(return_value="signed-token")
        auth_module.settings = types.SimpleNamespace(access_token_expire_minutes=30)

        database_module = types.ModuleType("app.database")
        database_module.get_db = lambda: None

        class FakeUserModel:
            id = FakeColumn("user_id")
            username = FakeColumn("username")

            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class FakeAuditLogModel:
            id = FakeColumn("id")
            timestamp = FakeColumn("timestamp")
            username = FakeColumn("username")
            action = FakeColumn("action")
            object_name = FakeColumn("object_name")
            ip_address = FakeColumn("ip_address")
            details = FakeColumn("details")
            user_id = FakeColumn("user_id")

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

        class FakeAuditLogResponse:
            @classmethod
            def from_orm(cls, log):
                return {
                    "id": log.id,
                    "timestamp": log.timestamp.isoformat(),
                    "username": log.username,
                    "action": log.action,
                    "object_name": log.object_name,
                    "ip_address": log.ip_address,
                    "details": log.details,
                }

        def placeholder(name):
            return type(name, (), {})

        schemas_module = types.ModuleType("app.schemas")
        for name in [
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
        schemas_module.AuditLogResponse = FakeAuditLogResponse
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
            f"app.test_day7_main_{id(audit_module)}",
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
        return module, audit_module, jsonable_encoder_mock, models_module

    def test_build_audit_query_applies_all_filters_and_desc_order(self):
        main_module, _, _, models_module = self._load_main_module()
        query = FakeQuery()
        db = mock.Mock()
        db.query.return_value = query
        date_from = datetime(2026, 3, 1, tzinfo=timezone.utc)
        date_to = datetime(2026, 3, 2, tzinfo=timezone.utc)

        result = main_module.build_audit_query(
            db,
            username=" alice ",
            action=" LOGIN ",
            object_name=" /users ",
            ip_address=" 127.0.0.1 ",
            date_from=date_from,
            date_to=date_to,
        )

        self.assertIs(result, query)
        db.query.assert_called_once_with(models_module.AuditLog)
        self.assertEqual(
            query.filters,
            [
                "username ILIKE %alice%",
                "action ILIKE %LOGIN%",
                "object_name ILIKE %/users%",
                "ip_address ILIKE %127.0.0.1%",
                ("timestamp", ">=", date_from),
                ("timestamp", "<=", date_to),
            ],
        )
        self.assertEqual(query.order_by_value, "timestamp DESC")

    def test_build_audit_filter_details_supports_full_payload_and_empty_case(self):
        main_module, _, _, _ = self._load_main_module()
        date_from = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
        date_to = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)

        details = main_module.build_audit_filter_details(
            username="alice",
            action="LOGIN_SUCCESS",
            object_name="/token",
            ip_address="127.0.0.1",
            date_from=date_from,
            date_to=date_to,
            limit=250,
            export_format="json",
        )

        self.assertEqual(
            details,
            "username=alice; action=LOGIN_SUCCESS; object_name=/token; ip_address=127.0.0.1; "
            f"date_from={date_from.isoformat()}; date_to={date_to.isoformat()}; limit=250; format=json",
        )
        self.assertEqual(main_module.build_audit_filter_details(), "no_filters")


class AuditEndpointTests(unittest.TestCase):
    @staticmethod
    def _load_main_module():
        return AuditHelpersTests._load_main_module()

    def test_get_audit_log_limits_rows_and_audits_view(self):
        main_module, audit_module, _, _ = self._load_main_module()
        rows = [
            types.SimpleNamespace(id=1, action="LOGIN_SUCCESS"),
            types.SimpleNamespace(id=2, action="CREATE_USER"),
        ]
        query = FakeQuery(rows=rows)
        main_module.build_audit_query = mock.Mock(return_value=query)
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        admin_user = types.SimpleNamespace(id=1, username="admin", role="admin")
        db = mock.Mock()
        date_from = datetime(2026, 3, 1, tzinfo=timezone.utc)

        result = main_module.get_audit_log(
            username="alice",
            action="LOGIN_SUCCESS",
            object_name="/token",
            ip_address="127.0.0.1",
            date_from=date_from,
            date_to=None,
            limit=50,
            request=request,
            db=db,
            current_user=admin_user,
        )

        self.assertIs(result, rows)
        main_module.build_audit_query.assert_called_once_with(
            db,
            username="alice",
            action="LOGIN_SUCCESS",
            object_name="/token",
            ip_address="127.0.0.1",
            date_from=date_from,
            date_to=None,
        )
        self.assertEqual(query.limit_value, 50)
        audit_module.create_user_audit_entry.assert_called_once_with(
            db,
            user=admin_user,
            action="AUDIT_VIEW",
            object_name="/audit",
            ip_address="127.0.0.1",
            details=f"username=alice; action=LOGIN_SUCCESS; object_name=/token; ip_address=127.0.0.1; date_from={date_from.isoformat()}; limit=50",
        )

    def test_logout_endpoint_logs_action_and_returns_success_payload(self):
        main_module, audit_module, _, _ = self._load_main_module()
        db = mock.Mock()
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        current_user = types.SimpleNamespace(id=1, username="admin", role="admin")

        result = main_module.logout(
            request=request,
            db=db,
            current_user=current_user,
        )

        self.assertEqual(result, {"status": "success", "message": "Logged out"})
        audit_module.create_user_audit_entry.assert_called_once_with(
            db,
            user=current_user,
            action="LOGOUT",
            object_name="/logout",
            ip_address="127.0.0.1",
            details="mode=client_side_logout",
        )

    def test_export_audit_log_returns_json_attachment_and_audits_export(self):
        main_module, audit_module, jsonable_encoder_mock, _ = self._load_main_module()
        log = types.SimpleNamespace(
            id=7,
            timestamp=datetime(2026, 3, 13, 12, 0, tzinfo=timezone.utc),
            username="alice",
            action="LOGIN_SUCCESS",
            object_name="/token",
            ip_address="127.0.0.1",
            details="token_type=bearer",
        )
        query = FakeQuery(rows=[log])
        main_module.build_audit_query = mock.Mock(return_value=query)
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="10.0.0.5"))
        admin_user = types.SimpleNamespace(id=1, username="admin", role="admin")
        db = mock.Mock()

        response = main_module.export_audit_log(
            format="json",
            username=None,
            action=None,
            object_name=None,
            ip_address=None,
            date_from=None,
            date_to=None,
            limit=2,
            request=request,
            db=db,
            current_user=admin_user,
        )

        self.assertEqual(query.limit_value, 2)
        self.assertEqual(response.media_type, "application/json")
        self.assertIn('attachment; filename="audit_logs_', response.headers["Content-Disposition"])
        self.assertTrue(response.headers["Content-Disposition"].endswith('.json"'))
        self.assertEqual(
            json.loads(response.body),
            [
                {
                    "id": 7,
                    "timestamp": "2026-03-13T12:00:00+00:00",
                    "username": "alice",
                    "action": "LOGIN_SUCCESS",
                    "object_name": "/token",
                    "ip_address": "127.0.0.1",
                    "details": "token_type=bearer",
                }
            ],
        )
        jsonable_encoder_mock.assert_called_once()
        audit_module.create_user_audit_entry.assert_called_once_with(
            db,
            user=admin_user,
            action="AUDIT_EXPORT",
            object_name="/audit/export",
            ip_address="10.0.0.5",
            details="limit=2; format=json",
        )

    def test_export_audit_log_returns_csv_attachment(self):
        main_module, audit_module, _, _ = self._load_main_module()
        log = types.SimpleNamespace(
            id=8,
            timestamp=datetime(2026, 3, 13, 13, 30, tzinfo=timezone.utc),
            username="bob",
            action="DELETE_USER",
            object_name="charlie",
            ip_address="127.0.0.1",
            details=None,
        )
        query = FakeQuery(rows=[log])
        main_module.build_audit_query = mock.Mock(return_value=query)
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="10.0.0.6"))
        admin_user = types.SimpleNamespace(id=1, username="admin", role="admin")
        db = mock.Mock()

        response = main_module.export_audit_log(
            format="csv",
            username="bob",
            action="DELETE_USER",
            object_name="charlie",
            ip_address="127.0.0.1",
            date_from=None,
            date_to=None,
            limit=3,
            request=request,
            db=db,
            current_user=admin_user,
        )

        self.assertEqual(query.limit_value, 3)
        self.assertEqual(response.media_type, "text/csv")
        self.assertIn('attachment; filename="audit_logs_', response.headers["Content-Disposition"])
        self.assertTrue(response.headers["Content-Disposition"].endswith('.csv"'))
        self.assertEqual(
            response.body.splitlines(),
            [
                "id,timestamp,username,action,object_name,ip_address,details",
                "8,2026-03-13T13:30:00+00:00,bob,DELETE_USER,charlie,127.0.0.1,",
            ],
        )
        audit_module.create_user_audit_entry.assert_called_once_with(
            db,
            user=admin_user,
            action="AUDIT_EXPORT",
            object_name="/audit/export",
            ip_address="10.0.0.6",
            details="username=bob; action=DELETE_USER; object_name=charlie; ip_address=127.0.0.1; limit=3; format=csv",
        )


if __name__ == "__main__":
    unittest.main()
