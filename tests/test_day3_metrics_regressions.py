import importlib.util
import os
import sys
import tempfile
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


class Day3SourceRegressionTests(unittest.TestCase):
    def test_metrics_route_and_response_model_exist(self):
        main_source = read_source("app/main.py")
        schemas_source = read_source("app/schemas.py")

        self.assertIn('@app.get("/metrics", response_model=ServerMetrics)', main_source)
        self.assertIn("def get_metrics(current_user: models.User = Depends(get_current_user))", main_source)
        self.assertIn("class ServerMetrics(BaseModel):", schemas_source)
        self.assertIn("hostname: str", schemas_source)
        self.assertIn("cpu_percent: float", schemas_source)
        self.assertIn("mem_percent: float", schemas_source)
        self.assertIn("disk_percent: float", schemas_source)
        self.assertIn("last_update: datetime", schemas_source)
        self.assertIn("status: str", schemas_source)
        self.assertIn("alerts: List[str]", schemas_source)

    def test_metrics_settings_and_status_logic_are_defined_in_source(self):
        config_source = read_source("app/config.py")
        system_source = read_source("app/system.py")

        self.assertIn('os.getenv("METRICS_DISK_PATH", "/host/proc/1/root")', config_source)
        self.assertIn('"METRICS_HOSTNAME_PATH"', config_source)
        self.assertIn('os.getenv("CPU_WARNING_THRESHOLD", "70")', config_source)
        self.assertIn('os.getenv("CPU_CRITICAL_THRESHOLD", "90")', config_source)
        self.assertIn('os.getenv("MEM_WARNING_THRESHOLD", "75")', config_source)
        self.assertIn('os.getenv("MEM_CRITICAL_THRESHOLD", "90")', config_source)
        self.assertIn('os.getenv("DISK_WARNING_THRESHOLD", "80")', config_source)
        self.assertIn('os.getenv("DISK_CRITICAL_THRESHOLD", "90")', config_source)
        self.assertIn('STATUS_OK = "ok"', system_source)
        self.assertIn('STATUS_WARNING = "warning"', system_source)
        self.assertIn('STATUS_CRITICAL = "critical"', system_source)
        self.assertIn('return socket.gethostname()', system_source)
        self.assertIn('datetime.now(timezone.utc)', system_source)


class MetricsConfigSettingsTests(unittest.TestCase):
    def test_metrics_defaults_target_host_namespace(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            config_module = load_module_from_path("test_day3_config_defaults", "app/config.py")
            settings = config_module.Settings()

        self.assertEqual(settings.metrics_disk_path, "/host/proc/1/root")
        self.assertEqual(settings.metrics_hostname_path, "/host/proc/sys/kernel/hostname")
        self.assertEqual(settings.cpu_warning_threshold, 70.0)
        self.assertEqual(settings.cpu_critical_threshold, 90.0)
        self.assertEqual(settings.mem_warning_threshold, 75.0)
        self.assertEqual(settings.mem_critical_threshold, 90.0)
        self.assertEqual(settings.disk_warning_threshold, 80.0)
        self.assertEqual(settings.disk_critical_threshold, 90.0)

    def test_metrics_thresholds_and_paths_can_be_overridden(self):
        with mock.patch.dict(
            os.environ,
            {
                "SERVER_NAME": "prod-node-01",
                "METRICS_DISK_PATH": "/srv/rootfs",
                "METRICS_HOSTNAME_PATH": "/srv/hostname",
                "METRICS_CPU_INTERVAL_SECONDS": "0.25",
                "CPU_WARNING_THRESHOLD": "61",
                "CPU_CRITICAL_THRESHOLD": "88",
                "MEM_WARNING_THRESHOLD": "62",
                "MEM_CRITICAL_THRESHOLD": "89",
                "DISK_WARNING_THRESHOLD": "63",
                "DISK_CRITICAL_THRESHOLD": "90.5",
            },
            clear=True,
        ):
            config_module = load_module_from_path("test_day3_config_overrides", "app/config.py")
            settings = config_module.Settings()

        self.assertEqual(settings.server_name, "prod-node-01")
        self.assertEqual(settings.metrics_disk_path, "/srv/rootfs")
        self.assertEqual(settings.metrics_hostname_path, "/srv/hostname")
        self.assertEqual(settings.metrics_cpu_interval_seconds, 0.25)
        self.assertEqual(settings.cpu_warning_threshold, 61.0)
        self.assertEqual(settings.cpu_critical_threshold, 88.0)
        self.assertEqual(settings.mem_warning_threshold, 62.0)
        self.assertEqual(settings.mem_critical_threshold, 89.0)
        self.assertEqual(settings.disk_warning_threshold, 63.0)
        self.assertEqual(settings.disk_critical_threshold, 90.5)


class SystemMetricsTests(unittest.TestCase):
    @staticmethod
    def _make_settings(**overrides):
        values = {
            "server_name": None,
            "metrics_hostname_path": "/host/proc/sys/kernel/hostname",
            "metrics_disk_path": "/host/proc/1/root",
            "metrics_cpu_interval_seconds": 0.5,
            "process_cpu_interval_seconds": 0.1,
            "cpu_warning_threshold": 70.0,
            "cpu_critical_threshold": 90.0,
            "mem_warning_threshold": 75.0,
            "mem_critical_threshold": 90.0,
            "disk_warning_threshold": 80.0,
            "disk_critical_threshold": 90.0,
        }
        values.update(overrides)
        return types.SimpleNamespace(**values)

    @staticmethod
    def _load_system_module(
        settings_obj,
        *,
        cpu_percent=12.34,
        mem_percent=45.67,
        disk_percent=23.45,
        disk_side_effect=None,
        socket_hostname="container-host",
    ):
        fastapi_module = types.ModuleType("fastapi")
        fastapi_module.HTTPException = FakeHTTPException

        psutil_module = types.ModuleType("psutil")

        class FakeProcess:
            pass

        class AccessDenied(Exception):
            pass

        class NoSuchProcess(Exception):
            pass

        class ZombieProcess(Exception):
            pass

        psutil_module.Process = FakeProcess
        psutil_module.AccessDenied = AccessDenied
        psutil_module.NoSuchProcess = NoSuchProcess
        psutil_module.ZombieProcess = ZombieProcess
        psutil_module.cpu_percent = mock.Mock(return_value=cpu_percent)
        psutil_module.virtual_memory = mock.Mock(
            return_value=types.SimpleNamespace(percent=mem_percent)
        )
        if disk_side_effect is None:
            psutil_module.disk_usage = mock.Mock(
                return_value=types.SimpleNamespace(percent=disk_percent)
            )
        else:
            psutil_module.disk_usage = mock.Mock(side_effect=disk_side_effect)
        psutil_module.process_iter = mock.Mock(return_value=[])
        psutil_module.wait_procs = mock.Mock(return_value=([], []))

        socket_module = types.ModuleType("socket")
        socket_module.gethostname = mock.Mock(return_value=socket_hostname)

        app_package = types.ModuleType("app")
        app_package.__path__ = []

        config_module = types.ModuleType("app.config")
        config_module.settings = settings_obj

        module_name = f"app.test_day3_system_{id(settings_obj)}_{str(cpu_percent).replace('.', '_')}"

        system_module = load_module_from_path(
            module_name,
            "app/system.py",
            {
                "fastapi": fastapi_module,
                "psutil": psutil_module,
                "socket": socket_module,
                "app": app_package,
                "app.config": config_module,
            },
        )
        return system_module, psutil_module, socket_module

    def test_resolve_hostname_prefers_explicit_server_name(self):
        settings_obj = self._make_settings(server_name="prod-node-01")
        system_module, _, socket_module = self._load_system_module(settings_obj)

        self.assertEqual(system_module._resolve_hostname(), "prod-node-01")
        socket_module.gethostname.assert_not_called()

    def test_resolve_hostname_reads_host_file_before_socket_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            hostname_path = Path(temp_dir) / "hostname"
            hostname_path.write_text("host-machine-01\n", encoding="utf-8")
            settings_obj = self._make_settings(metrics_hostname_path=str(hostname_path))
            system_module, _, socket_module = self._load_system_module(settings_obj)

            self.assertEqual(system_module._resolve_hostname(), "host-machine-01")
            socket_module.gethostname.assert_not_called()

    def test_resolve_hostname_falls_back_to_socket(self):
        settings_obj = self._make_settings(metrics_hostname_path="/missing/hostname")
        system_module, _, socket_module = self._load_system_module(
            settings_obj,
            socket_hostname="socket-host-01",
        )

        self.assertEqual(system_module._resolve_hostname(), "socket-host-01")
        socket_module.gethostname.assert_called_once_with()

    def test_resolve_disk_usage_falls_back_to_root_when_host_path_is_unavailable(self):
        settings_obj = self._make_settings(metrics_disk_path="/host/proc/1/root")
        system_module, psutil_module, _ = self._load_system_module(
            settings_obj,
            disk_side_effect=[OSError("not-mounted"), types.SimpleNamespace(percent=33.3)],
        )

        disk = system_module._resolve_disk_usage()

        self.assertEqual(disk.percent, 33.3)
        self.assertEqual(
            psutil_module.disk_usage.call_args_list,
            [mock.call("/host/proc/1/root"), mock.call("/")],
        )

    def test_build_metrics_status_uses_ok_warning_and_critical_rules(self):
        settings_obj = self._make_settings()
        system_module, _, _ = self._load_system_module(settings_obj)

        ok_status, ok_alerts = system_module._build_metrics_status(69.9, 74.9, 79.9)
        warning_status, warning_alerts = system_module._build_metrics_status(70.0, 60.0, 60.0)
        critical_status, critical_alerts = system_module._build_metrics_status(20.0, 90.0, 95.0)

        self.assertEqual(ok_status, "ok")
        self.assertEqual(ok_alerts, [])
        self.assertEqual(warning_status, "warning")
        self.assertEqual(warning_alerts, ["CPU usage is high: 70.0%"])
        self.assertEqual(critical_status, "critical")
        self.assertEqual(
            critical_alerts,
            [
                "Memory usage is critical: 90.0%",
                "Disk usage is critical: 95.0%",
            ],
        )

    def test_get_server_metrics_returns_full_contract_with_timezone_aware_timestamp(self):
        settings_obj = self._make_settings(server_name="prod-node-01")
        system_module, psutil_module, _ = self._load_system_module(
            settings_obj,
            cpu_percent=12.345,
            mem_percent=45.678,
            disk_percent=90.126,
        )

        metrics = system_module.get_server_metrics()

        self.assertEqual(
            set(metrics),
            {
                "hostname",
                "cpu_percent",
                "mem_percent",
                "disk_percent",
                "last_update",
                "status",
                "alerts",
            },
        )
        self.assertEqual(metrics["hostname"], "prod-node-01")
        self.assertEqual(metrics["cpu_percent"], 12.35)
        self.assertEqual(metrics["mem_percent"], 45.68)
        self.assertEqual(metrics["disk_percent"], 90.13)
        self.assertIsInstance(metrics["last_update"], datetime)
        self.assertIs(metrics["last_update"].tzinfo, timezone.utc)
        self.assertEqual(metrics["status"], "critical")
        self.assertEqual(metrics["alerts"], ["Disk usage is critical: 90.1%"])
        psutil_module.cpu_percent.assert_called_once_with(interval=0.5)
        psutil_module.virtual_memory.assert_called_once_with()
        psutil_module.disk_usage.assert_called_once_with("/host/proc/1/root")


class MetricsEndpointTests(unittest.TestCase):
    @staticmethod
    def _load_main_module(system_metrics_result):
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
        system_module.get_server_metrics = mock.Mock(return_value=system_metrics_result)
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
            f"app.test_day3_main_{id(system_metrics_result)}",
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
        return module, system_module

    def test_metrics_endpoint_delegates_to_system_module(self):
        metrics_payload = {
            "hostname": "prod-node-01",
            "cpu_percent": 10.0,
            "mem_percent": 20.0,
            "disk_percent": 30.0,
            "last_update": datetime.now(timezone.utc),
            "status": "ok",
            "alerts": [],
        }
        main_module, system_module = self._load_main_module(metrics_payload)

        result = main_module.get_metrics(current_user=object())

        self.assertIs(result, metrics_payload)
        system_module.get_server_metrics.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
