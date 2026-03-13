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
        self.default_admin_username = os.getenv("DEFAULT_ADMIN_USERNAME")
        self.default_admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD")
        self.default_admin_is_active = _as_bool(
            os.getenv("DEFAULT_ADMIN_IS_ACTIVE"),
            True,
        )


settings = Settings()
