import importlib.util
import os
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


class FakeResponse:
    def __init__(self):
        self.headers = {}


class _OneshotContext:
    def __init__(self, process):
        self.process = process

    def __enter__(self):
        self.process._inside_oneshot = True
        return self.process

    def __exit__(self, exc_type, exc, tb):
        self.process._inside_oneshot = False
        return False


class FakeProcess:
    def __init__(
        self,
        pid,
        *,
        info=None,
        cpu_reads=None,
        mem_value=0.0,
        runtime_name=None,
        runtime_owner=None,
        runtime_status=None,
        prime_exception=None,
        build_exception=None,
    ):
        process_info = {
            "pid": pid,
            "name": None,
            "status": None,
            "username": None,
        }
        if info:
            process_info.update(info)

        self.pid = pid
        self.info = process_info
        self._cpu_reads = list(cpu_reads or [0.0])
        self._last_cpu = self._cpu_reads[-1]
        self._mem_value = mem_value
        self._runtime_name = runtime_name if runtime_name is not None else process_info["name"]
        self._runtime_owner = (
            runtime_owner if runtime_owner is not None else process_info["username"]
        )
        self._runtime_status = (
            runtime_status if runtime_status is not None else process_info["status"]
        )
        self._prime_exception = prime_exception
        self._build_exception = build_exception
        self._inside_oneshot = False
        self.cpu_call_count = 0

    def oneshot(self):
        return _OneshotContext(self)

    def cpu_percent(self, interval=None):
        self.cpu_call_count += 1
        if not self._inside_oneshot and self._prime_exception and self.cpu_call_count == 1:
            raise self._prime_exception
        if self._inside_oneshot and self._build_exception:
            raise self._build_exception
        if self._cpu_reads:
            value = self._cpu_reads.pop(0)
            self._last_cpu = value
            return value
        return self._last_cpu

    def memory_percent(self):
        if self._inside_oneshot and self._build_exception:
            raise self._build_exception
        return self._mem_value

    def name(self):
        if self._inside_oneshot and self._build_exception:
            raise self._build_exception
        return self._runtime_name

    def username(self):
        if self._inside_oneshot and self._build_exception:
            raise self._build_exception
        return self._runtime_owner

    def status(self):
        if self._inside_oneshot and self._build_exception:
            raise self._build_exception
        return self._runtime_status


class Day4SourceRegressionTests(unittest.TestCase):
    def test_processes_route_supports_filter_sort_pagination_for_authenticated_users(self):
        main_source = read_source("app/main.py")

        self.assertIn('@app.get("/processes", response_model=List[ProcessInfo])', main_source)
        self.assertIn("filter_name: Optional[str] = Query(None, min_length=1, max_length=255)", main_source)
        self.assertIn("sort_by: ProcessSortField = ProcessSortField.PID", main_source)
        self.assertIn("sort_direction: SortDirection = SortDirection.ASC", main_source)
        self.assertIn("skip: int = Query(0, ge=0)", main_source)
        self.assertIn("settings.processes_default_limit", main_source)
        self.assertIn("settings.processes_max_limit", main_source)
        self.assertIn("current_user: models.User = Depends(get_current_user)", main_source)
        self.assertIn('response.headers["X-Total-Count"] = str(total)', main_source)
        self.assertIn('response.headers["X-Page-Skip"] = str(skip)', main_source)
        self.assertIn('response.headers["X-Page-Limit"] = str(limit)', main_source)
        self.assertIn('response.headers["X-Sort-By"] = sort_by.value', main_source)
        self.assertIn('response.headers["X-Sort-Direction"] = sort_direction.value', main_source)

    def test_process_sort_contract_and_psutil_error_handling_exist(self):
        schemas_source = read_source("app/schemas.py")
        system_source = read_source("app/system.py")

        self.assertIn('PID = "pid"', schemas_source)
        self.assertIn('NAME = "name"', schemas_source)
        self.assertIn('CPU = "cpu"', schemas_source)
        self.assertIn('MEM = "mem"', schemas_source)
        self.assertIn('STATUS = "status"', schemas_source)
        self.assertIn('OWNER = "owner"', schemas_source)
        self.assertIn('ASC = "asc"', schemas_source)
        self.assertIn('DESC = "desc"', schemas_source)
        self.assertIn('PROCESS_SORT_FIELDS = {"pid", "name", "cpu", "mem", "status", "owner"}', system_source)
        self.assertIn("_prime_process_cpu_counters(processes)", system_source)
        self.assertIn('psutil.process_iter(', system_source)
        self.assertIn('ad_value=None', system_source)
        self.assertIn("except psutil.ZombieProcess", system_source)
        self.assertIn("except psutil.AccessDenied", system_source)
        self.assertIn("except psutil.NoSuchProcess", system_source)


class ProcessPaginationConfigTests(unittest.TestCase):
    def test_process_pagination_defaults_are_stable(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            config_module = load_module_from_path("test_day4_config_defaults", "app/config.py")
            settings = config_module.Settings()

        self.assertEqual(settings.processes_default_limit, 100)
        self.assertEqual(settings.processes_max_limit, 500)

    def test_process_default_limit_is_clamped_to_maximum(self):
        with mock.patch.dict(
            os.environ,
            {
                "PROCESSES_MAX_LIMIT": "25",
                "PROCESSES_DEFAULT_LIMIT": "80",
            },
            clear=True,
        ):
            config_module = load_module_from_path("test_day4_config_clamp", "app/config.py")
            settings = config_module.Settings()

        self.assertEqual(settings.processes_max_limit, 25)
        self.assertEqual(settings.processes_default_limit, 25)


class SystemProcessesTests(unittest.TestCase):
    @staticmethod
    def _make_settings(**overrides):
        values = {
            "process_cpu_interval_seconds": 0.0,
            "processes_default_limit": 100,
            "processes_max_limit": 500,
        }
        values.update(overrides)
        return types.SimpleNamespace(**values)

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

        psutil_module.Process = FakeProcess
        psutil_module.AccessDenied = AccessDenied
        psutil_module.NoSuchProcess = NoSuchProcess
        psutil_module.ZombieProcess = ZombieProcess
        psutil_module.process_iter = mock.Mock(return_value=[])
        psutil_module.wait_procs = mock.Mock(return_value=([], []))
        psutil_module.cpu_percent = mock.Mock(return_value=0.0)
        psutil_module.virtual_memory = mock.Mock(return_value=types.SimpleNamespace(percent=0.0))
        psutil_module.disk_usage = mock.Mock(return_value=types.SimpleNamespace(percent=0.0))

        time_module = types.ModuleType("time")
        time_module.sleep = mock.Mock()

        socket_module = types.ModuleType("socket")
        socket_module.gethostname = mock.Mock(return_value="test-host")

        app_package = types.ModuleType("app")
        app_package.__path__ = []

        config_module = types.ModuleType("app.config")
        config_module.settings = settings_obj

        module_name = f"app.test_day4_system_{id(settings_obj)}"
        system_module = load_module_from_path(
            module_name,
            "app/system.py",
            {
                "fastapi": fastapi_module,
                "psutil": psutil_module,
                "time": time_module,
                "socket": socket_module,
                "app": app_package,
                "app.config": config_module,
            },
        )
        return system_module, psutil_module, time_module

    def test_prime_process_cpu_counters_ignores_psutil_errors_and_sleeps(self):
        settings_obj = self._make_settings(process_cpu_interval_seconds=0.25)
        system_module, psutil_module, time_module = self._load_system_module(settings_obj)

        processes = [
            FakeProcess(1, cpu_reads=[0.0]),
            FakeProcess(2, prime_exception=psutil_module.AccessDenied("denied")),
            FakeProcess(3, prime_exception=psutil_module.ZombieProcess("zombie")),
            FakeProcess(4, prime_exception=psutil_module.NoSuchProcess("gone")),
        ]

        system_module._prime_process_cpu_counters(processes)

        self.assertEqual(processes[0].cpu_call_count, 1)
        self.assertEqual(processes[1].cpu_call_count, 1)
        self.assertEqual(processes[2].cpu_call_count, 1)
        self.assertEqual(processes[3].cpu_call_count, 1)
        time_module.sleep.assert_called_once_with(0.25)

    def test_build_process_info_normalizes_missing_fields_and_rounds_metrics(self):
        settings_obj = self._make_settings()
        system_module, _, _ = self._load_system_module(settings_obj)

        process = FakeProcess(
            11,
            info={"name": None, "status": None, "username": None},
            cpu_reads=[7.777],
            mem_value=2.3456,
            runtime_name="py-worker",
            runtime_owner="alice",
            runtime_status="running",
        )

        result = system_module._build_process_info(process)

        self.assertEqual(
            result,
            {
                "pid": 11,
                "name": "py-worker",
                "cpu": 7.78,
                "mem": 2.35,
                "status": "running",
                "owner": "alice",
            },
        )

    def test_build_process_info_handles_access_denied(self):
        settings_obj = self._make_settings()
        system_module, psutil_module, _ = self._load_system_module(settings_obj)

        process = FakeProcess(
            12,
            info={"name": None, "status": None, "username": None},
            build_exception=psutil_module.AccessDenied("denied"),
        )

        result = system_module._build_process_info(process)

        self.assertEqual(result["name"], "pid-12")
        self.assertEqual(result["cpu"], 0.0)
        self.assertEqual(result["mem"], 0.0)
        self.assertEqual(result["status"], "access_denied")
        self.assertEqual(result["owner"], "restricted")

    def test_build_process_info_handles_zombie_and_nosuchprocess(self):
        settings_obj = self._make_settings()
        system_module, psutil_module, _ = self._load_system_module(settings_obj)

        zombie_process = FakeProcess(
            13,
            info={"name": "worker", "status": "sleeping", "username": "bob"},
            build_exception=psutil_module.ZombieProcess("zombie"),
        )
        missing_process = FakeProcess(
            14,
            info={"name": "worker", "status": "sleeping", "username": "bob"},
            build_exception=psutil_module.NoSuchProcess("gone"),
        )

        zombie_result = system_module._build_process_info(zombie_process)
        missing_result = system_module._build_process_info(missing_process)

        self.assertEqual(zombie_result["name"], "worker")
        self.assertEqual(zombie_result["cpu"], 0.0)
        self.assertEqual(zombie_result["mem"], 0.0)
        self.assertEqual(zombie_result["status"], "zombie")
        self.assertEqual(zombie_result["owner"], "bob")
        self.assertIsNone(missing_result)

    def test_sort_processes_uses_casefold_and_pid_tiebreaker_for_text_fields(self):
        settings_obj = self._make_settings()
        system_module, _, _ = self._load_system_module(settings_obj)
        processes = [
            {"pid": 5, "name": "Worker", "cpu": 1.0, "mem": 1.0, "status": "running", "owner": "alice"},
            {"pid": 2, "name": "api", "cpu": 2.0, "mem": 2.0, "status": "sleeping", "owner": "bob"},
            {"pid": 3, "name": "worker", "cpu": 3.0, "mem": 3.0, "status": "stopped", "owner": "carol"},
        ]

        sorted_processes = system_module._sort_processes(processes, "name", reverse=False)

        self.assertEqual([item["pid"] for item in sorted_processes], [2, 3, 5])

    def test_get_processes_filters_sorts_and_paginates(self):
        settings_obj = self._make_settings(processes_default_limit=2, processes_max_limit=3)
        system_module, psutil_module, _ = self._load_system_module(settings_obj)
        processes = [
            FakeProcess(
                10,
                info={"name": "Python API", "status": "running", "username": "alice"},
                cpu_reads=[0.0, 11.11],
                mem_value=1.5,
            ),
            FakeProcess(
                3,
                info={"name": "py-helper", "status": "sleeping", "username": "bob"},
                cpu_reads=[0.0, 33.33],
                mem_value=3.1,
            ),
            FakeProcess(
                7,
                info={"name": "redis", "status": "running", "username": "root"},
                cpu_reads=[0.0, 22.22],
                mem_value=2.2,
            ),
            FakeProcess(
                9,
                info={"name": "py-gone", "status": "sleeping", "username": "nobody"},
                cpu_reads=[0.0],
                build_exception=psutil_module.NoSuchProcess("gone"),
            ),
        ]
        psutil_module.process_iter.return_value = processes

        paginated_processes, total = system_module.get_processes(
            filter_name=" PY ",
            sort_by="cpu",
            sort_direction="desc",
            skip=1,
            limit=5,
        )

        self.assertEqual(total, 2)
        self.assertEqual([item["pid"] for item in paginated_processes], [10])
        self.assertEqual(paginated_processes[0]["cpu"], 11.11)
        psutil_module.process_iter.assert_called_once_with(
            ["pid", "name", "status", "username"],
            ad_value=None,
        )

    def test_get_processes_clamps_limit_and_uses_text_sort(self):
        settings_obj = self._make_settings(processes_default_limit=1, processes_max_limit=2)
        system_module, psutil_module, _ = self._load_system_module(settings_obj)
        psutil_module.process_iter.return_value = [
            FakeProcess(
                5,
                info={"name": "worker", "status": "running", "username": "alice"},
                cpu_reads=[0.0, 1.0],
                mem_value=1.0,
            ),
            FakeProcess(
                1,
                info={"name": "API", "status": "running", "username": "bob"},
                cpu_reads=[0.0, 2.0],
                mem_value=2.0,
            ),
            FakeProcess(
                2,
                info={"name": "api", "status": "running", "username": "carol"},
                cpu_reads=[0.0, 3.0],
                mem_value=3.0,
            ),
        ]

        paginated_processes, total = system_module.get_processes(
            sort_by="name",
            sort_direction="asc",
            skip=0,
            limit=99,
        )

        self.assertEqual(total, 3)
        self.assertEqual([item["pid"] for item in paginated_processes], [1, 2])


class ProcessesEndpointTests(unittest.TestCase):
    @staticmethod
    def _load_main_module(processes_result):
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
        system_module.get_processes = mock.Mock(return_value=processes_result)
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
            PID=types.SimpleNamespace(value="pid"),
            NAME=types.SimpleNamespace(value="name"),
            CPU=types.SimpleNamespace(value="cpu"),
        )
        schemas_module.SortDirection = types.SimpleNamespace(
            ASC=types.SimpleNamespace(value="asc"),
            DESC=types.SimpleNamespace(value="desc"),
        )

        dependencies_module = types.ModuleType("app.dependencies")
        dependencies_module.get_current_user = lambda: None
        dependencies_module.get_current_admin_user = lambda: None

        module = load_module_from_path(
            f"app.test_day4_main_{id(processes_result)}",
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
        return module, system_module, schemas_module

    def test_processes_endpoint_delegates_to_system_and_sets_pagination_headers(self):
        payload = ([{"pid": 10, "name": "python"}], 17)
        main_module, system_module, schemas_module = self._load_main_module(payload)
        response = FakeResponse()
        limited_user = types.SimpleNamespace(id=2, username="limited", role="limited")

        result = main_module.list_processes(
            response=response,
            filter_name="python",
            sort_by=schemas_module.ProcessSortField.NAME,
            sort_direction=schemas_module.SortDirection.DESC,
            skip=5,
            limit=20,
            current_user=limited_user,
        )

        self.assertEqual(result, payload[0])
        system_module.get_processes.assert_called_once_with(
            filter_name="python",
            sort_by="name",
            sort_direction="desc",
            skip=5,
            limit=20,
        )
        self.assertEqual(
            response.headers,
            {
                "X-Total-Count": "17",
                "X-Page-Skip": "5",
                "X-Page-Limit": "20",
                "X-Sort-By": "name",
                "X-Sort-Direction": "desc",
            },
        )


if __name__ == "__main__":
    unittest.main()
