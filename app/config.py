import os
from typing import Optional


def _as_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: Optional[str], default: int) -> int:
    if value is None:
        return default
    return int(value)


class Settings:
    def __init__(self) -> None:
        self.database_url = os.getenv(
            "DATABASE_URL",
            "postgresql://user:password@db:5432/monitoring",
        )
        self.secret_key = os.getenv("SECRET_KEY")
        self.algorithm = os.getenv("ALGORITHM", "HS256")
        self.access_token_expire_minutes = _as_int(
            os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"),
            30,
        )
        self.default_admin_username = (
            os.getenv("DEFAULT_ADMIN_USERNAME")
            or os.getenv("INITIAL_ADMIN_USERNAME")
        )
        self.default_admin_password = (
            os.getenv("DEFAULT_ADMIN_PASSWORD")
            or os.getenv("INITIAL_ADMIN_PASSWORD")
        )
        self.default_admin_is_active = _as_bool(
            os.getenv("DEFAULT_ADMIN_IS_ACTIVE") or os.getenv("INITIAL_ADMIN_IS_ACTIVE"),
            True,
        )
        self.metrics_cpu_interval_seconds = float(
            os.getenv("METRICS_CPU_INTERVAL_SECONDS", "1.0")
        )
        self.process_cpu_interval_seconds = float(
            os.getenv("PROCESS_CPU_INTERVAL_SECONDS", "0.1")
        )
        self.processes_max_limit = max(
            1,
            _as_int(os.getenv("PROCESSES_MAX_LIMIT"), 500),
        )
        self.processes_default_limit = min(
            max(1, _as_int(os.getenv("PROCESSES_DEFAULT_LIMIT"), 100)),
            self.processes_max_limit,
        )
        self.server_name = os.getenv("SERVER_NAME")
        self.metrics_disk_path = os.getenv("METRICS_DISK_PATH", "/host/proc/1/root")
        self.metrics_hostname_path = os.getenv(
            "METRICS_HOSTNAME_PATH",
            "/host/proc/sys/kernel/hostname",
        )
        self.cpu_warning_threshold = float(os.getenv("CPU_WARNING_THRESHOLD", "70"))
        self.cpu_critical_threshold = float(os.getenv("CPU_CRITICAL_THRESHOLD", "90"))
        self.mem_warning_threshold = float(os.getenv("MEM_WARNING_THRESHOLD", "75"))
        self.mem_critical_threshold = float(os.getenv("MEM_CRITICAL_THRESHOLD", "90"))
        self.disk_warning_threshold = float(os.getenv("DISK_WARNING_THRESHOLD", "80"))
        self.disk_critical_threshold = float(os.getenv("DISK_CRITICAL_THRESHOLD", "90"))


settings = Settings()
