"""Assess IOC intelligence freshness independently of risk scoring."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class SourceFreshness:
    source_name: str
    status: str
    last_seen: str | None
    collected_at: str | None
    age_days: int | None
    explanation: str


def _parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO timestamp, returning None when missing or invalid."""
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(
            value.strip()[:-1] + "+00:00"
            if value.strip().endswith("Z")
            else value.strip()
        )
    except (ValueError, TypeError, OverflowError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def assess_source_freshness(
    source: dict,
    *,
    now: datetime | None = None,
) -> SourceFreshness:
    """Classify observation freshness using source_last_seen.

    Thresholds: fresh <= 7 days; aging > 7 and <= 30 days;
    stale > 30 days. Missing, invalid, or future last-seen
    timestamps are unknown. Collection time is reported separately.
    """
    reference_time = (
        now if now is not None else datetime.now(timezone.utc)
    )
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)
    reference_time = reference_time.astimezone(timezone.utc)

    last_seen_raw = source.get("source_last_seen")
    collected_at = source.get("collected_at")
    last_seen = _parse_timestamp(last_seen_raw)

    if last_seen is None:
        status = "unknown"
        age_days = None
        explanation = "Last-seen observation timestamp is missing or invalid."
    else:
        age = reference_time - last_seen
        if age < timedelta(0):
            status = "unknown"
            age_days = None
            explanation = "Last-seen timestamp is in the future."
        else:
            age_days = age.days
            if age <= timedelta(days=7):
                status = "fresh"
                explanation = "Last observed within the past 7 days."
            elif age <= timedelta(days=30):
                status = "aging"
                explanation = "Last observed more than 7 and up to 30 days ago."
            else:
                status = "stale"
                explanation = "Last observed more than 30 days ago."

    return SourceFreshness(
        source_name=str(source.get("source_name") or "unknown"),
        status=status,
        last_seen=last_seen_raw if isinstance(last_seen_raw, str) else None,
        collected_at=collected_at if isinstance(collected_at, str) else None,
        age_days=age_days,
        explanation=explanation,
    )


def assess_ioc_freshness(
    sources: list[dict],
    *,
    now: datetime | None = None,
) -> dict:
    """Assess each source and summarize IOC freshness without hiding unknowns."""
    assessments = [
        assess_source_freshness(source, now=now)
        for source in sources
    ]

    counts = {status: 0 for status in ("fresh", "aging", "stale", "unknown")}
    for assessment in assessments:
        counts[assessment.status] += 1

    known_statuses = [
        assessment.status
        for assessment in assessments
        if assessment.status != "unknown"
    ]

    if not assessments or not known_statuses:
        overall_status = "unknown"
    elif "fresh" in known_statuses:
        overall_status = "fresh"
    elif "aging" in known_statuses:
        overall_status = "aging"
    else:
        overall_status = "stale"

    return {
        "overall_status": overall_status,
        "source_count": len(assessments),
        "status_counts": counts,
        "sources": [
            {
                "source_name": item.source_name,
                "status": item.status,
                "last_seen": item.last_seen,
                "collected_at": item.collected_at,
                "age_days": item.age_days,
                "explanation": item.explanation,
            }
            for item in assessments
        ],
        "policy": {
            "fresh_days_max": 7,
            "aging_days_max": 30,
            "future_timestamp": "unknown",
            "missing_timestamp": "unknown",
        },
    }
