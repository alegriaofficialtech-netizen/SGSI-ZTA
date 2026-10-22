import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginInput(InputModel):
    username: str = Field(min_length=1, max_length=80)
    password: SecretStr = Field(min_length=1, max_length=128)
    remember: bool = False


class UserCreate(InputModel):
    username: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,79}$")
    display_name: str = Field(min_length=2, max_length=120)
    department: str = Field(min_length=2, max_length=80)
    password: SecretStr
    roles: list[str] = Field(min_length=1, max_length=7)

    @field_validator("password")
    @classmethod
    def strong_password(cls, value: SecretStr) -> SecretStr:
        password = value.get_secret_value()
        if not 14 <= len(password) <= 128 or not all(
            re.search(pattern, password) for pattern in [r"[A-Z]", r"[a-z]", r"\d", r"[^A-Za-z0-9]"]
        ):
            raise ValueError("Use 14–128 characters with upper/lowercase, number and symbol")
        return value


class UserUpdate(InputModel):
    display_name: str | None = Field(default=None, min_length=2, max_length=120)
    department: str | None = Field(default=None, min_length=2, max_length=80)
    roles: list[str] | None = Field(default=None, min_length=1, max_length=7)
    is_active: bool | None = None


class UserPublic(BaseModel):
    id: int
    username: str
    display_name: str
    department: str
    roles: list[str]
    groups: list[str]
    is_active: bool
    mfa_required: bool
    mfa_enabled: bool = False
    last_login: datetime | None
    created_at: datetime


class AuditPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: datetime
    username: str
    action: str
    resource: str
    decision: str
    ip: str
    detail: str
    policy_decision_id: str | None = None
