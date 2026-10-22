"""Pure typed policy evaluation: no SQL, requests, token processing or persistence."""
from collections.abc import Sequence
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, StrictBool

from app.policies.context import PolicyContext, utc
from app.policies.types import (
    Action,
    ConditionOperator,
    ConditionType,
    Decision,
    DeviceTrust,
    PolicyEffect,
    ReasonCode,
)
from app.schemas.policies import (
    ConditionInput,
    PolicyCode,
    Priority,
    Resource,
    RiskScore,
    SessionAge,
)


class PolicyRule(BaseModel):
    """Validate structured stored conditions before they enter the pure engine."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str
    policy_code: PolicyCode
    resource: Resource
    action: Action
    effect: PolicyEffect
    priority: Priority = 100
    enabled: StrictBool = True
    role_names: frozenset[str] = frozenset()
    require_mfa: StrictBool = False
    max_risk_score: RiskScore | None = None
    required_device_trust: DeviceTrust | None = None
    session_max_age_minutes: SessionAge | None = None
    conditions: tuple[ConditionInput, ...] = ()


@dataclass(frozen=True)
class EngineOutcome:
    decision: Decision
    reason_code: ReasonCode
    policy_id: str | None = None
    policy_code: str | None = None


def condition_matches(condition: ConditionInput, context: PolicyContext) -> bool | None:
    """Three-valued predicates: None is an unknown fact, never a matching zero."""
    kind, operator, expected = condition.condition_type, condition.operator, condition.value
    if kind == ConditionType.TIME_WINDOW:
        moment = utc(context.request_time)
        minute = moment.hour * 60 + moment.minute

        def minutes(value: str) -> int:
            hour, minute = map(int, value.split(":"))
            return hour * 60 + minute

        start, end = minutes(expected["start"]), minutes(expected["end"])
        return start <= minute < end if start < end else minute >= start or minute < end
    if kind == ConditionType.ROLE:
        choices = expected if operator == ConditionOperator.IN else [expected]
        return bool(context.roles.intersection(choices))
    actual = {
        ConditionType.MFA: context.mfa_verified,
        ConditionType.ASSET_CRITICALITY: context.asset_criticality if context.asset_id else None,
        ConditionType.RISK_LEVEL: context.effective_risk_level if context.asset_id else None,
        ConditionType.RISK_SCORE: context.effective_risk_score if context.asset_id else None,
        ConditionType.DEVICE_TRUST: context.device_trust,
        ConditionType.SESSION_AGE: context.session_age_minutes,
    }[kind]
    if actual is None:
        return None
    if operator == ConditionOperator.EQ:
        return actual == expected
    if operator == ConditionOperator.IN:
        return actual in expected
    if operator == ConditionOperator.LTE:
        return actual <= expected
    if operator == ConditionOperator.GTE:
        return actual >= expected
    # ConditionInput rejects this combination; never execute arbitrary operators.
    return False


_TRUST_RANK = {DeviceTrust.UNTRUSTED: 0, DeviceTrust.LIMITED: 1, DeviceTrust.TRUSTED: 2}


def _device_reason(actual: DeviceTrust, expected: Sequence[str]) -> ReasonCode:
    if all(_TRUST_RANK[actual] < _TRUST_RANK[DeviceTrust(trust)] for trust in expected):
        return ReasonCode.DEVICE_UNTRUSTED
    return ReasonCode.DEFAULT_DENY


def _condition_reason(condition: ConditionInput, ctx: PolicyContext) -> ReasonCode:
    if condition.condition_type == ConditionType.ROLE:
        return ReasonCode.ROLE_NOT_ALLOWED
    if condition.condition_type == ConditionType.DEVICE_TRUST:
        values = (
            condition.value if condition.operator == ConditionOperator.IN else [condition.value]
        )
        return _device_reason(ctx.device_trust, values)
    if condition.operator == ConditionOperator.LTE:
        if condition.condition_type == ConditionType.RISK_SCORE:
            return ReasonCode.RISK_THRESHOLD_EXCEEDED
        if condition.condition_type == ConditionType.SESSION_AGE:
            return ReasonCode.SESSION_TOO_OLD
    return ReasonCode.DEFAULT_DENY


def _requirements(rule: PolicyRule, ctx: PolicyContext) -> tuple[list[ReasonCode | None], bool]:
    failures: list[ReasonCode | None] = []
    if rule.role_names and not rule.role_names.intersection(ctx.roles):
        failures.append(ReasonCode.ROLE_NOT_ALLOWED)
    if rule.required_device_trust is not None and ctx.device_trust != rule.required_device_trust:
        failures.append(_device_reason(ctx.device_trust, [rule.required_device_trust]))
    if rule.max_risk_score is not None:
        if ctx.asset_id is None or ctx.effective_risk_score is None:
            failures.append(None)
        elif ctx.effective_risk_score > rule.max_risk_score:
            failures.append(ReasonCode.RISK_THRESHOLD_EXCEEDED)
    if rule.session_max_age_minutes is not None:
        if ctx.session_age_minutes is None:
            failures.append(None)
        elif ctx.session_age_minutes > rule.session_max_age_minutes:
            failures.append(ReasonCode.SESSION_TOO_OLD)
    mfa_values = {
        condition.value for condition in rule.conditions
        if condition.condition_type == ConditionType.MFA
    }
    needs_mfa = rule.require_mfa or True in mfa_values
    # An impossible MFA configuration must not promise that escalation can grant.
    if needs_mfa and False in mfa_values:
        failures.append(ReasonCode.DEFAULT_DENY)
    for condition in rule.conditions:
        if condition.condition_type == ConditionType.MFA and condition.value is True:
            continue
        matches = condition_matches(condition, ctx)
        if matches is None:
            failures.append(None)
        elif not matches:
            failures.append(_condition_reason(condition, ctx))
    return failures, needs_mfa and not ctx.mfa_verified


def _explicit_reason(rule: PolicyRule, ctx: PolicyContext) -> ReasonCode:
    # A generic DENY is not evidence that a device caused it.
    if ctx.device_trust == DeviceTrust.UNTRUSTED and (
        rule.required_device_trust == DeviceTrust.UNTRUSTED
        or any(condition.condition_type == ConditionType.DEVICE_TRUST
               for condition in rule.conditions)
    ):
        return ReasonCode.DEVICE_UNTRUSTED
    return ReasonCode.EXPLICIT_DENY


def evaluate(context: PolicyContext, policies: Sequence[PolicyRule]) -> EngineOutcome:
    """DENY > missing MFA > ALLOW; descending priority then code only within tiers."""
    applicable = sorted(
        (rule for rule in policies if rule.enabled
         and rule.resource == context.resource and rule.action == context.action),
        key=lambda rule: (-rule.priority, rule.policy_code, rule.id),
    )
    denies, escalations, allows = [], [], []
    diagnostics: list[tuple[PolicyRule, list[ReasonCode | None]]] = []
    for rule in applicable:
        failures, missing_mfa = _requirements(rule, context)
        if failures:
            if rule.effect == PolicyEffect.ALLOW:
                diagnostics.append((rule, failures))
            continue
        if missing_mfa:
            escalations.append(rule)
        elif rule.effect == PolicyEffect.DENY:
            denies.append(rule)
        else:
            allows.append(rule)
    for candidates, decision, reason in (
        (denies, Decision.DENY, None),
        (escalations, Decision.MFA_REQUIRED, ReasonCode.MFA_REQUIRED),
        (allows, Decision.ALLOW, ReasonCode.POLICY_ALLOW),
    ):
        if candidates:
            chosen = candidates[0]
            return EngineOutcome(
                decision, reason or _explicit_reason(chosen, context),
                chosen.id, chosen.policy_code,
            )
    if diagnostics:
        rule, failures = diagnostics[0]
        # Unknown or unmapped facts cannot justify a more specific denial.
        if None not in failures and ReasonCode.DEFAULT_DENY not in failures:
            return EngineOutcome(Decision.DENY, failures[0], rule.id, rule.policy_code)
    return EngineOutcome(Decision.DENY, ReasonCode.DEFAULT_DENY)
