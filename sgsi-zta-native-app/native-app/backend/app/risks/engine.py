"""Canonical academic calculation, used by writes, seed and matrix/preview."""

from app.models.risks import Impact, Probability, RiskLevel

THRESHOLDS = (
    (4, RiskLevel.LOW),
    (9, RiskLevel.MEDIUM),
    (16, RiskLevel.HIGH),
    (25, RiskLevel.CRITICAL),
)


def validate_risk_values(probability, impact):
    if isinstance(probability, bool) or isinstance(impact, bool):
        raise ValueError("Probability and impact must be integers from 1 to 5")
    return Probability(probability), Impact(impact)


def calculate_score(probability, impact):
    p, i = validate_risk_values(probability, impact)
    return int(p) * int(i)


def classify_risk(score):
    if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 25:
        raise ValueError("Score must be an integer from 1 to 25")
    return next(level for maximum, level in THRESHOLDS if score <= maximum)
