from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", hide_input_in_errors=True)

    database_url: str
    jwt_secret: SecretStr
    mfa_encryption_key: SecretStr
    mfa_challenge_seconds: int = 300
    mfa_max_attempts: int = 5
    demo_password: SecretStr | None = None
    cookie_secure: bool = False
    allowed_origins: list[str] = ["http://127.0.0.1:8090", "http://localhost:8090"]
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "backend", "testserver"]
    access_minutes: int = 10
    refresh_hours: int = 8
    remember_days: int = 14
    login_limit: int = 10
    login_peer_limit: int = 100
    login_window_seconds: int = 900
    jwt_issuer: str = "sgsi-zta-native"
    jwt_audience: str = "sgsi-zta-browser"
    monitoring_data_root: str | None = None

    def get_monitoring_data_root(self) -> str:
        if self.monitoring_data_root:
            return self.monitoring_data_root
        from pathlib import Path
        backend_dir = Path(__file__).resolve().parent.parent
        root_option = backend_dir.parent / "monitoring-data"
        if root_option.is_dir():
            return str(root_option.resolve())
        backend_option = backend_dir / "monitoring-data"
        if backend_option.is_dir():
            return str(backend_option.resolve())
        return str(root_option.resolve())

    @field_validator("mfa_encryption_key")
    @classmethod
    def validate_mfa_key(cls, value: SecretStr) -> SecretStr:
        from cryptography.fernet import Fernet

        Fernet(value.get_secret_value().encode())
        return value

    @field_validator("jwt_secret")
    @classmethod
    def validate_secret(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < 48 or "CHANGE_ME" in raw:
            raise ValueError("JWT_SECRET must contain at least 48 random characters")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
