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


class FakeManagedProcess:
    def __init__(self, pid, *, name=None, children=None, initial_nice=0):
        self.pid = pid
        self._name = name or f"proc-{pid}"
        self._children = list(children or [])
        self._nice_value = initial_nice
        self.kill = mock.Mock()
        self.children = mock.Mock(return_value=self._children)

    def name(self):
        return self._name

    def nice(self, value=None):
        if value is None:
            return self._nice_value
        self._nice_value = value
        return self._nice_value


class Day5SourceRegressionTests(unittest.TestCase):
    def test_process_control_route_uses_admin_dependency_and_confirmation(self):
        main_source = read_source("app/main.py")

        self.assertIn('@app.post("/processes/{pid}", response_model=ProcessActionResult)', main_source)
        self.assertIn("current_user: models.User = Depends(get_current_admin_user)", main_source)
        self.assertIn("if not action_data.confirm:", main_source)
        self.assertIn('raise HTTPException(status_code=400, detail="Confirmation required")', main_source)
        self.assertIn('"PROCESS_CONTROL"', main_source)
        self.assertIn('"PROCESS_CONTROL_FAILED"', main_source)

    def test_manage_process_supports_kill_tree_and_priority_contract(self):
        schemas_source = read_source("app/schemas.py")
        system_source = read_source("app/system.py")

        self.assertIn('pattern="^(kill|kill_tree|priority)$"', schemas_source)
        self.assertIn('if action == "priority" and priority is None:', schemas_source)
        self.assertIn('if action in {"kill", "kill_tree"} and priority is not None:', schemas_source)
        self.assertIn('PROCESS_ACTION_TIMEOUT_SECONDS = 3', system_source)
        self.assertIn('if action == "kill":', system_source)
        self.assertIn('if action == "kill_tree":', system_source)
        self.assertIn('if action == "priority":', system_source)
        self.assertIn('raise HTTPException(status_code=404, detail=f"Process {pid} not found")', system_source)
        self.assertIn('raise HTTPException(status_code=403, detail=f"Access denied for process {pid}")', system_source)
        self.assertIn('raise HTTPException(status_code=400, detail=str(exc))', system_source)


class SystemProcessControlTests(unittest.TestCase):
    @staticmethod
    def _make_settings():
        return types.SimpleNamespace(
            server_name=None,
            metrics_hostname_path="/host/proc/sys/kernel/hostname",
            metrics_disk_path="/host/proc/1/root",
            metrics_cpu_interval_seconds=0.0,
            process_cpu_interval_seconds=0.0,
            processes_default_limit=100,
            processes_max_limit=500,
            cpu_warning_threshold=70.0,
            cpu_critical_threshold=90.0,
            mem_warning_threshold=75.0,
            mem_critical_threshold=90.0,
            disk_warning_threshold=80.0,
            disk_critical_threshold=90.0,
        )

    @staticmethod
    def _load_system_module(settings_obj):
        fastapi_module = types.ModuleType("fastapi")
        fastapi_module.HTTPException = FakeHTTPException

        psutil_module = types.ModuleType("psutil")

        class AccessDenied(Exception):
            pass

        class NoSuchProcess(Exception):
            pass

        class ZombieProcess(Exception):
            pass

        psutil_module.AccessDenied = AccessDenied
        psutil_module.NoSuchProcess = NoSuchProcess
        psutil_module.ZombieProcess = ZombieProcess
        psutil_module.Process = mock.Mock()
        psutil_module.wait_procs = mock.Mock(return_value=([], []))
        psutil_module.process_iter = mock.Mock(return_value=[])
        psutil_module.cpu_percent = mock.Mock(return_value=0.0)
        psutil_module.virtual_memory = mock.Mock(return_value=types.SimpleNamespace(percent=0.0))
        psutil_module.disk_usage = mock.Mock(return_value=types.SimpleNamespace(percent=0.0))

        socket_module = types.ModuleType("socket")
        socket_module.gethostname = mock.Mock(return_value="test-host")

        time_module = types.ModuleType("time")
        time_module.sleep = mock.Mock()

        app_package = types.ModuleType("app")
        app_package.__path__ = []

        config_module = types.ModuleType("app.config")
        config_module.settings = settings_obj

        module = load_module_from_path(
            f"app.test_day5_system_{id(settings_obj)}",
            "app/system.py",
            {
                "fastapi": fastapi_module,
                "psutil": psutil_module,
                "socket": socket_module,
                "time": time_module,
                "app": app_package,
                "app.config": config_module,
            },
        )
        return module, psutil_module

    def test_safe_process_name_falls_back_for_denied_or_missing_process(self):
        settings_obj = self._make_settings()
        system_module, psutil_module = self._load_system_module(settings_obj)

        denied_process = mock.Mock(pid=7)
        denied_process.name.side_effect = psutil_module.AccessDenied("denied")
        missing_process = mock.Mock(pid=8)
        missing_process.name.side_effect = psutil_module.NoSuchProcess("gone")

        self.assertEqual(system_module._safe_process_name(denied_process), "pid-7")
        self.assertEqual(system_module._safe_process_name(missing_process), "8")

    def test_ensure_process_stopped_raises_409_when_processes_are_still_alive(self):
        settings_obj = self._make_settings()
        system_module, psutil_module = self._load_system_module(settings_obj)
        alive_process = types.SimpleNamespace(pid=42)
        psutil_module.wait_procs.return_value = ([], [alive_process])

        with self.assertRaises(FakeHTTPException) as context:
            system_module._ensure_process_stopped([alive_process])

        self.assertEqual(context.exception.status_code, 409)
        self.assertEqual(context.exception.detail, "Processes did not stop in time: 42")
        psutil_module.wait_procs.assert_called_once_with(
            [alive_process],
            timeout=3,
        )

    def test_manage_process_kill_returns_success_payload(self):
        settings_obj = self._make_settings()
        system_module, psutil_module = self._load_system_module(settings_obj)
        target_process = FakeManagedProcess(101, name="python")
        psutil_module.Process.return_value = target_process

        result = system_module.manage_process(101, "kill")

        target_process.kill.assert_called_once_with()
        psutil_module.wait_procs.assert_called_once_with([target_process], timeout=3)
        self.assertEqual(
            result,
            {
                "status": "success",
                "message": "Process 101 killed",
                "pid": 101,
                "action": "kill",
                "process_name": "python",
                "affected_pids": [101],
            },
        )

    def test_manage_process_kill_tree_kills_children_and_target(self):
        settings_obj = self._make_settings()
        system_module, psutil_module = self._load_system_module(settings_obj)
        child1 = FakeManagedProcess(201, name="child-1")
        child2 = FakeManagedProcess(202, name="child-2")
        target_process = FakeManagedProcess(200, name="parent", children=[child1, child2])
        psutil_module.Process.return_value = target_process

        result = system_module.manage_process(200, "kill_tree")

        target_process.children.assert_called_once_with(recursive=True)
        child2.kill.assert_called_once_with()
        child1.kill.assert_called_once_with()
        target_process.kill.assert_called_once_with()
        psutil_module.wait_procs.assert_called_once_with([child1, child2, target_process], timeout=3)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["message"], "Process tree 200 killed")
        self.assertEqual(result["process_name"], "parent")
        self.assertEqual(result["affected_pids"], [201, 202, 200])

    def test_manage_process_priority_updates_nice_value(self):
        settings_obj = self._make_settings()
        system_module, psutil_module = self._load_system_module(settings_obj)
        target_process = FakeManagedProcess(301, name="worker", initial_nice=5)
        psutil_module.Process.return_value = target_process

        result = system_module.manage_process(301, "priority", priority=-10)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["message"], "Priority for process 301 set to -10")
        self.assertEqual(result["previous_priority"], 5)
        self.assertEqual(result["current_priority"], -10)
        self.assertEqual(target_process.nice(), -10)

    def test_manage_process_returns_clear_http_errors(self):
        settings_obj = self._make_settings()
        system_module, psutil_module = self._load_system_module(settings_obj)

        psutil_module.Process.side_effect = psutil_module.NoSuchProcess("gone")
        with self.assertRaises(FakeHTTPException) as missing_context:
            system_module.manage_process(404, "kill")
        self.assertEqual(missing_context.exception.status_code, 404)
        self.assertEqual(missing_context.exception.detail, "Process 404 not found")

        psutil_module.Process.side_effect = psutil_module.AccessDenied("denied")
        with self.assertRaises(FakeHTTPException) as denied_context:
            system_module.manage_process(403, "kill")
        self.assertEqual(denied_context.exception.status_code, 403)
        self.assertEqual(denied_context.exception.detail, "Access denied for process 403")

    def test_manage_process_rejects_invalid_priority_and_unsupported_action(self):
        settings_obj = self._make_settings()
        system_module, psutil_module = self._load_system_module(settings_obj)
        psutil_module.Process.return_value = FakeManagedProcess(500, name="worker")

        with self.assertRaises(FakeHTTPException) as missing_priority:
            system_module.manage_process(500, "priority")
        self.assertEqual(missing_priority.exception.status_code, 400)
        self.assertEqual(missing_priority.exception.detail, "Priority value is required")

        with self.assertRaises(FakeHTTPException) as bad_priority:
            system_module.manage_process(500, "priority", priority=20)
        self.assertEqual(bad_priority.exception.status_code, 400)
        self.assertEqual(bad_priority.exception.detail, "Priority must be between -20 and 19")

        with self.assertRaises(FakeHTTPException) as unsupported_action:
            system_module.manage_process(500, "restart")
        self.assertEqual(unsupported_action.exception.status_code, 400)
        self.assertEqual(unsupported_action.exception.detail, "Unsupported action: restart")


class ProcessControlEndpointTests(unittest.TestCase):
    @staticmethod
    def _load_main_module(manage_process_result=None, manage_process_side_effect=None):
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
        system_module.manage_process = mock.Mock(return_value=manage_process_result)
        if manage_process_side_effect is not None:
            system_module.manage_process.side_effect = manage_process_side_effect

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
            f"app.test_day5_main_{id(system_module.manage_process)}",
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
        return module, system_module, audit_module

    def test_control_process_requires_confirmation(self):
        main_module, system_module, audit_module = self._load_main_module(manage_process_result={})
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        action_data = types.SimpleNamespace(action="kill", priority=None, confirm=False)

        with self.assertRaises(FakeHTTPException) as context:
            main_module.control_process(
                pid=100,
                action_data=action_data,
                request=request,
                db=mock.Mock(),
                current_user=types.SimpleNamespace(id=1, username="admin"),
            )

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "Confirmation required")
        system_module.manage_process.assert_not_called()
        audit_module.create_user_audit_entry.assert_not_called()

    def test_control_process_logs_successful_action(self):
        manage_result = {
            "status": "success",
            "message": "Priority for process 123 set to -5",
            "pid": 123,
            "action": "priority",
            "process_name": "worker",
            "affected_pids": [123],
            "previous_priority": 0,
            "current_priority": -5,
        }
        main_module, system_module, audit_module = self._load_main_module(
            manage_process_result=manage_result
        )
        db = mock.Mock()
        admin_user = types.SimpleNamespace(id=1, username="admin")
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        action_data = types.SimpleNamespace(action="priority", priority=-5, confirm=True)

        result = main_module.control_process(
            pid=123,
            action_data=action_data,
            request=request,
            db=db,
            current_user=admin_user,
        )

        self.assertIs(result, manage_result)
        system_module.manage_process.assert_called_once_with(123, "priority", -5)
        audit_module.create_user_audit_entry.assert_called_once_with(
            db,
            user=admin_user,
            action="PROCESS_CONTROL",
            object_name="123",
            ip_address="127.0.0.1",
            details="action=priority; process_name=worker; affected_pids=123; previous_priority=0; current_priority=-5",
        )

    def test_control_process_logs_http_failures_and_reraises_them(self):
        error = FakeHTTPException(status_code=403, detail="Access denied for process 55")
        main_module, system_module, audit_module = self._load_main_module(
            manage_process_side_effect=error
        )
        db = mock.Mock()
        admin_user = types.SimpleNamespace(id=1, username="admin")
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        action_data = types.SimpleNamespace(action="priority", priority=10, confirm=True)

        with self.assertRaises(FakeHTTPException) as context:
            main_module.control_process(
                pid=55,
                action_data=action_data,
                request=request,
                db=db,
                current_user=admin_user,
            )

        self.assertIs(context.exception, error)
        audit_module.create_user_audit_entry.assert_called_once_with(
            db,
            user=admin_user,
            action="PROCESS_CONTROL_FAILED",
            object_name="55",
            ip_address="127.0.0.1",
            details="action=priority; error=Access denied for process 55; priority=10",
        )

    def test_control_process_wraps_unexpected_errors_into_500_and_audits(self):
        main_module, system_module, audit_module = self._load_main_module(
            manage_process_side_effect=RuntimeError("kernel failure")
        )
        db = mock.Mock()
        admin_user = types.SimpleNamespace(id=1, username="admin")
        request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
        action_data = types.SimpleNamespace(action="kill_tree", priority=None, confirm=True)

        with self.assertRaises(FakeHTTPException) as context:
            main_module.control_process(
                pid=88,
                action_data=action_data,
                request=request,
                db=db,
                current_user=admin_user,
            )

        self.assertEqual(context.exception.status_code, 500)
        self.assertEqual(context.exception.detail, "kernel failure")
        audit_module.create_user_audit_entry.assert_called_once_with(
            db,
            user=admin_user,
            action="PROCESS_CONTROL_FAILED",
            object_name="88",
            ip_address="127.0.0.1",
            details="action=kill_tree; error=kernel failure",
        )


if __name__ == "__main__":
    unittest.main()
