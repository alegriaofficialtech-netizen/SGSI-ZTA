"""Pure engine operators and conflict tiers require no client or database facts."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from itertools import permutations

import pytest

from app.models.assets import Criticality
from app.models.risks import RiskLevel
from app.policies.types import Action, Decision, DeviceTrust, PolicyEffect, ReasonCode
from app.schemas.policies import ConditionInput


def context(**changes):
    from app.policies.context import PolicyContext

    values = dict(
        user_id=2, roles=frozenset({"medico"}), session_id="validated-session",
        mfa_verified=True, session_age_minutes=5.0, device_id=None,
        device_trust=DeviceTrust.TRUSTED, asset_id=1, asset_criticality=Criticality.HIGH,
        effective_risk_score=12, effective_risk_level=RiskLevel.HIGH, effective_risk_id=3,
        resource="clinical-demo", action=Action.READ,
        request_time=datetime(2026, 10, 4, 12, 0, tzinfo=UTC), simulation=False,
    )
    return PolicyContext(**(values | changes))


def rule(code="POL-TEST-001", **changes):
    from app.policies.engine import PolicyRule

    values = dict(id=code, policy_code=code, resource="clinical-demo",
                  action="read", effect=PolicyEffect.ALLOW, priority=100,
                  enabled=True, role_names=frozenset({"medico"}), conditions=())
    return PolicyRule(**(values | changes))


def evaluate(ctx=None, rules=None):
    from app.policies.engine import evaluate as engine_evaluate

    return engine_evaluate(ctx or context(), rules if rules is not None else [rule()])


@pytest.mark.parametrize("kind,operator,value,expected", [
    ("ROLE", "EQ", "medico", True), ("ROLE", "EQ", "admision", False),
    ("ROLE", "IN", ["admin-ti", "medico"], True), ("ROLE", "IN", ["auditor"], False),
    ("MFA", "EQ", True, True), ("MFA", "EQ", False, False),
    ("ASSET_CRITICALITY", "EQ", "HIGH", True),
    ("ASSET_CRITICALITY", "EQ", "LOW", False),
    ("ASSET_CRITICALITY", "IN", ["LOW", "HIGH"], True),
    ("ASSET_CRITICALITY", "IN", ["MEDIUM"], False),
    ("RISK_LEVEL", "EQ", "HIGH", True), ("RISK_LEVEL", "EQ", "CRITICAL", False),
    ("RISK_LEVEL", "IN", ["HIGH", "CRITICAL"], True),
    ("RISK_LEVEL", "IN", ["LOW"], False),
    ("DEVICE_TRUST", "EQ", "TRUSTED", True), ("DEVICE_TRUST", "EQ", "LIMITED", False),
    ("DEVICE_TRUST", "IN", ["TRUSTED", "LIMITED"], True),
    ("DEVICE_TRUST", "IN", ["UNTRUSTED"], False),
    ("RISK_SCORE", "EQ", 12, True), ("RISK_SCORE", "EQ", 13, False),
    ("RISK_SCORE", "LTE", 12, True), ("RISK_SCORE", "LTE", 11, False),
    ("RISK_SCORE", "GTE", 12, True), ("RISK_SCORE", "GTE", 13, False),
    ("SESSION_AGE", "EQ", 5, True), ("SESSION_AGE", "EQ", 4, False),
    ("SESSION_AGE", "LTE", 5, True), ("SESSION_AGE", "LTE", 4, False),
    ("SESSION_AGE", "GTE", 5, True), ("SESSION_AGE", "GTE", 6, False),
])
def test_all_typed_operators(kind, operator, value, expected):
    from app.policies.engine import condition_matches

    condition = ConditionInput(condition_type=kind, operator=operator, value=value)
    assert condition_matches(condition, context()) is expected


@pytest.mark.parametrize("start,end,hour,minute,second,expected", [
    ("08:00", "17:00", 7, 59, 59, False), ("08:00", "17:00", 8, 0, 0, True),
    ("08:00", "17:00", 16, 59, 59, True), ("08:00", "17:00", 17, 0, 0, False),
    ("22:00", "06:00", 21, 59, 59, False), ("22:00", "06:00", 22, 0, 0, True),
    ("22:00", "06:00", 23, 59, 59, True), ("22:00", "06:00", 0, 0, 0, True),
    ("22:00", "06:00", 5, 59, 59, True), ("22:00", "06:00", 6, 0, 0, False),
])
def test_utc_window_boundaries(start, end, hour, minute, second, expected):
    from app.policies.engine import condition_matches

    condition = ConditionInput(condition_type="TIME_WINDOW", operator="BETWEEN",
                               value={"start": start, "end": end})
    utc_time = datetime(2026, 10, 4, hour, minute, second, tzinfo=UTC)
    for moment in [utc_time, utc_time.astimezone(timezone(timedelta(hours=-5))),
                   utc_time.replace(tzinfo=None)]:
        assert condition_matches(condition, context(request_time=moment)) is expected


@pytest.mark.parametrize("effect,missing,expected", [
    ("DENY", True, "DENY"), ("DENY", False, "DENY"),
    ("ALLOW", True, "MFA_REQUIRED"), ("ALLOW", False, "ALLOW"),
])
def test_all_tier_conflicts_ignore_cross_tier_priority(effect, missing, expected):
    policies = [rule("POL-ALLOW", priority=1000),
                rule("POL-MFA", priority=0, require_mfa=True)]
    if effect == "DENY":
        policies.append(rule("POL-DENY", effect="DENY", priority=0))
    for ordering in permutations(policies):
        outcome = evaluate(context(mfa_verified=not missing), ordering)
        assert outcome.decision == expected
        assert outcome.policy_code == (
            "POL-DENY" if effect == "DENY" else "POL-MFA" if missing else "POL-ALLOW"
        )


@pytest.mark.parametrize("effect,missing", [("ALLOW", False), ("DENY", False), ("ALLOW", True)])
def test_priority_descending_and_code_ascending_within_tier(effect, missing):
    policies = [rule("POL-Z", priority=200, effect=effect, require_mfa=missing),
                rule("POL-A", priority=200, effect=effect, require_mfa=missing),
                rule("POL-LOW", priority=0, effect=effect, require_mfa=missing)]
    for ordering in permutations(policies):
        assert evaluate(context(mfa_verified=not missing), ordering).policy_code == "POL-A"


@pytest.mark.parametrize("changes", [
    {"role_names": frozenset({"auditor"})}, {"required_device_trust": "LIMITED"},
    {"max_risk_score": 11}, {"session_max_age_minutes": 1},
    {"conditions": (ConditionInput(condition_type="ASSET_CRITICALITY",
                                  operator="EQ", value="LOW"),)},
])
def test_non_mfa_requirements_must_pass_before_mfa_candidate(changes):
    outcome = evaluate(context(mfa_verified=False), [rule(require_mfa=True, **changes), rule()])
    assert outcome.decision == Decision.ALLOW


def test_condition_mfa_required_and_explicit_false():
    required = rule(conditions=(ConditionInput(condition_type="MFA", operator="EQ", value=True),))
    assert evaluate(context(mfa_verified=False), [required]).decision == Decision.MFA_REQUIRED
    password_only = rule(conditions=(
        ConditionInput(condition_type="MFA", operator="EQ", value=False),))
    assert evaluate(context(mfa_verified=False), [password_only]).decision == Decision.ALLOW
    outcome = evaluate(context(mfa_verified=True), [password_only])
    assert outcome.reason_code == ReasonCode.DEFAULT_DENY


@pytest.mark.parametrize("kind,operator,value", [
    ("ASSET_CRITICALITY", "EQ", "LOW"), ("RISK_LEVEL", "IN", ["LOW"]),
    ("RISK_SCORE", "LTE", 25), ("SESSION_AGE", "LTE", 10080),
])
def test_unknown_internal_facts_fail_closed_without_fake_reason(kind, operator, value):
    missing = context(asset_id=None, asset_criticality=None, effective_risk_score=None,
                      effective_risk_level=None, session_age_minutes=None, simulation=True)
    result = evaluate(missing, [rule(require_mfa=True, conditions=(
        ConditionInput(condition_type=kind, operator=operator, value=value),))])
    assert result.decision == Decision.DENY and result.reason_code == ReasonCode.DEFAULT_DENY


def test_unknown_max_risk_does_not_use_response_zero_sentinel():
    assert evaluate(context(asset_id=None, effective_risk_score=None,
                            effective_risk_level=None), [rule(max_risk_score=20)]
                    ).reason_code == ReasonCode.DEFAULT_DENY


@pytest.mark.parametrize("changes,reason", [
    ({"role_names": frozenset({"admision"})}, "ROLE_NOT_ALLOWED"),
    ({"required_device_trust": "TRUSTED"}, "DEVICE_UNTRUSTED"),
    ({"max_risk_score": 10}, "RISK_THRESHOLD_EXCEEDED"),
    ({"session_max_age_minutes": 1}, "SESSION_TOO_OLD"),
    ({"conditions": (ConditionInput(condition_type="RISK_SCORE", operator="LTE", value=10),)},
     "RISK_THRESHOLD_EXCEEDED"),
    ({"conditions": (ConditionInput(condition_type="SESSION_AGE", operator="LTE", value=1),)},
     "SESSION_TOO_OLD"),
])
def test_reason_codes_require_actual_facts(changes, reason):
    assert evaluate(context(device_trust=DeviceTrust.LIMITED), [rule(**changes)]
                    ).reason_code == reason


@pytest.mark.parametrize("condition", [
    ConditionInput(condition_type="RISK_SCORE", operator="GTE", value=20),
    ConditionInput(condition_type="SESSION_AGE", operator="GTE", value=20),
    ConditionInput(condition_type="ASSET_CRITICALITY", operator="EQ", value="LOW"),
])
def test_non_quantitative_failure_does_not_fabricate_threshold(condition):
    assert evaluate(rules=[rule(conditions=(condition,))]).reason_code == ReasonCode.DEFAULT_DENY


def test_default_deny_filters_resource_action_and_disabled():
    assert evaluate(rules=[]).reason_code == ReasonCode.DEFAULT_DENY
    for changes in [{"enabled": False}, {"resource": "unknown-resource"}, {"action": "update"}]:
        assert evaluate(rules=[rule(**changes)]).reason_code == ReasonCode.DEFAULT_DENY


def test_pure_engine_does_not_mutate_inputs():
    ctx, policy = context(), rule()
    assert evaluate(ctx, [policy]).decision == Decision.ALLOW
    assert ctx == replace(ctx)
    with pytest.raises((AttributeError, ValueError)):
        ctx.mfa_verified = False


@pytest.mark.parametrize("invalid", [
    {"condition_type": "ROLE", "operator": "EQ", "value": "medico' OR true"},
    {"condition_type": "RISK_SCORE", "operator": "LTE", "value": True},
    {"condition_type": "TIME_WINDOW", "operator": "BETWEEN",
     "value": {"start": "00:00", "end": "00:00"}},
])
def test_invalid_structured_conditions_never_enter_engine(invalid):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        rule(conditions=(invalid,))


@pytest.mark.parametrize("operator", ["EQ", "LTE", "GTE"])
def test_simulation_none_session_age_never_matches(operator):
    condition = ConditionInput(condition_type="SESSION_AGE", operator=operator, value=0)
    ctx = context(session_age_minutes=None, session_id=None, simulation=True)
    assert evaluate(ctx, [rule(conditions=(condition,))]).reason_code == ReasonCode.DEFAULT_DENY


def test_contradictory_mfa_requirements_fail_closed():
    outcome = evaluate(context(mfa_verified=False), [rule(require_mfa=True, conditions=(
        ConditionInput(condition_type="MFA", operator="EQ", value=False),))])
    assert outcome.decision == Decision.DENY and outcome.reason_code == ReasonCode.DEFAULT_DENY


def test_valid_deny_beats_mfa_and_allow_at_both_priority_extremes():
    for deny_priority, other_priority in [(0, 1000), (1000, 0)]:
        rules = [rule("POL-DENY", effect="DENY", priority=deny_priority),
                 rule("POL-MFA", require_mfa=True, priority=other_priority),
                 rule("POL-ALLOW", priority=other_priority)]
        for ordering in permutations(rules):
            outcome = evaluate(context(mfa_verified=False), ordering)
            assert outcome.decision == Decision.DENY and outcome.reason_code == "EXPLICIT_DENY"


def test_inapplicable_deny_does_not_block_allow():
    assert evaluate(rules=[rule("POL-DENY", effect="DENY", role_names=frozenset({"auditor"})),
                           rule()]).decision == Decision.ALLOW
