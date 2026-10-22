from enum import StrEnum


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MFA_REQUIRED = "MFA_REQUIRED"


class PolicyEffect(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class DeviceTrust(StrEnum):
    TRUSTED = "TRUSTED"
    LIMITED = "LIMITED"
    UNTRUSTED = "UNTRUSTED"


class DeviceStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class ReasonCode(StrEnum):
    POLICY_ALLOW = "POLICY_ALLOW"
    EXPLICIT_DENY = "EXPLICIT_DENY"
    MFA_REQUIRED = "MFA_REQUIRED"
    ROLE_NOT_ALLOWED = "ROLE_NOT_ALLOWED"
    DEVICE_UNTRUSTED = "DEVICE_UNTRUSTED"
    RISK_THRESHOLD_EXCEEDED = "RISK_THRESHOLD_EXCEEDED"
    SESSION_TOO_OLD = "SESSION_TOO_OLD"
    DEFAULT_DENY = "DEFAULT_DENY"


class Action(StrEnum):
    READ = "read"
    READ_SENSITIVE = "read_sensitive"
    CREATE = "create"
    UPDATE = "update"
    DISABLE = "disable"
    APPROVE = "approve"
    EXPORT = "export"


class ConditionType(StrEnum):
    ROLE = "ROLE"
    MFA = "MFA"
    ASSET_CRITICALITY = "ASSET_CRITICALITY"
    RISK_LEVEL = "RISK_LEVEL"
    RISK_SCORE = "RISK_SCORE"
    DEVICE_TRUST = "DEVICE_TRUST"
    SESSION_AGE = "SESSION_AGE"
    TIME_WINDOW = "TIME_WINDOW"


class ConditionOperator(StrEnum):
    EQ = "EQ"
    IN = "IN"
    LTE = "LTE"
    GTE = "GTE"
    BETWEEN = "BETWEEN"


MAX_PRIORITY = 1000
MAX_SESSION_AGE_MINUTES = 10080
MAX_RISK_SCORE = 25

