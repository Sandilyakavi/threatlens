
from dataclasses import dataclass


@dataclass(frozen=True)
class RiskFactor:
    name: str
    points: int
    explanation: str


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    factors: tuple[RiskFactor, ...]

    @property
    def reasons(self) -> list[str]:
        return [factor.explanation for factor in self.factors]


def assess_risk(
    *,
    confidence: int,
    source_count: int = 1,
    threat_type: str | None = None,
    tags: list[str] | None = None,
) -> RiskAssessment:
    """Calculate an explainable risk score from available IOC evidence."""

    if not 0 <= confidence <= 100:
        raise ValueError("confidence must be between 0 and 100")

    if source_count < 1:
        raise ValueError("source_count must be at least 1")

    factors: list[RiskFactor] = []

    # Confidence contributes at most 40 points.
    confidence_points = round(confidence * 0.4)

    if confidence_points:
        factors.append(
            RiskFactor(
                name="confidence",
                points=confidence_points,
                explanation=(
                    f"Feed confidence is {confidence}/100 "
                    f"(+{confidence_points})."
                ),
            )
        )

    # Additional sources contribute at most 30 points.
    # This assumes the recorded sources provide corroboration.
    source_points = min(max(source_count - 1, 0) * 15, 30)

    if source_points:
        factors.append(
            RiskFactor(
                name="source_corroboration",
                points=source_points,
                explanation=(
                    f"Observed by {source_count} distinct sources "
                    f"(+{source_points})."
                ),
            )
        )

    # Threat context contributes at most 20 points.
    normalized_threat_type = (
        threat_type.strip().lower()
        if isinstance(threat_type, str) and threat_type.strip()
        else None
    )

    if normalized_threat_type:
        factors.append(
            RiskFactor(
                name="threat_context",
                points=20,
                explanation=(
                    f"Threat type is identified as "
                    f"{threat_type.strip()} (+20)."
                ),
            )
        )

    # Tags contribute at most 10 points.
    # Source-identification labels describe provenance, not threat severity.
    source_identification_tags = {
        "threatfox",
        "feodo-tracker",
    }

    meaningful_tags = sorted(
        {
            tag.strip().casefold()
            for tag in (tags or [])
            if isinstance(tag, str)
            and tag.strip()
            and tag.strip().casefold() not in source_identification_tags
        }
    )

    # Do not count the exact threat type again as a tag.
    if normalized_threat_type:
        meaningful_tags = [
            tag
            for tag in meaningful_tags
            if tag != normalized_threat_type
        ]

    if meaningful_tags:
        factors.append(
            RiskFactor(
                name="tags",
                points=10,
                explanation=(
                    "Feed provides contextual tags: "
                    f"{', '.join(meaningful_tags)} (+10)."
                ),
            )
        )

    score = min(sum(factor.points for factor in factors), 100)

    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return RiskAssessment(
        score=score,
        level=level,
        factors=tuple(factors),
    )
