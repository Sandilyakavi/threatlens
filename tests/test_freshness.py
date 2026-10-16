from datetime import datetime, timedelta, timezone

import pytest

from threatlens.detection.freshness import (
    assess_ioc_freshness,
    assess_source_freshness,
)


NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)


def source(last_seen, collected_at="2026-10-16T11:00:00+00:00"):
    return {
        "source_name": "test-feed",
        "source_last_seen": last_seen,
        "collected_at": collected_at,
    }


@pytest.mark.parametrize(
    ("days_old", "expected"),
    [
        (0, "fresh"),
        (7, "fresh"),
        (8, "aging"),
        (30, "aging"),
        (31, "stale"),
    ],
)
def test_observation_age_thresholds(days_old, expected):
    observed = (NOW - timedelta(days=days_old)).isoformat()
    result = assess_source_freshness(source(observed), now=NOW)
    assert result.status == expected
    assert result.age_days == days_old


@pytest.mark.parametrize("last_seen", [None, "", "not-a-date"])
def test_missing_or_invalid_last_seen_is_unknown(last_seen):
    result = assess_source_freshness(source(last_seen), now=NOW)
    assert result.status == "unknown"
    assert result.age_days is None


def test_future_last_seen_is_unknown():
    future = (NOW + timedelta(minutes=1)).isoformat()
    result = assess_source_freshness(source(future), now=NOW)
    assert result.status == "unknown"
    assert "future" in result.explanation


def test_naive_timestamp_is_treated_as_utc():
    result = assess_source_freshness(
        source("2026-10-15T12:00:00"),
        now=NOW,
    )
    assert result.status == "fresh"
    assert result.age_days == 1


def test_collection_time_does_not_replace_last_seen():
    result = assess_source_freshness(
        source(
            "2026-08-01T12:00:00+00:00",
            collected_at="2026-10-16T11:00:00+00:00",
        ),
        now=NOW,
    )
    assert result.status == "stale"
    assert result.collected_at == "2026-10-16T11:00:00+00:00"


def test_ioc_summary_preserves_unknown_sources():
    result = assess_ioc_freshness(
        [
            source("2026-10-15T12:00:00+00:00"),
            source(None),
        ],
        now=NOW,
    )
    assert result["overall_status"] == "fresh"
    assert result["status_counts"] == {
        "fresh": 1,
        "aging": 0,
        "stale": 0,
        "unknown": 1,
    }


def test_all_unknown_sources_produce_unknown_summary():
    result = assess_ioc_freshness([source(None)], now=NOW)
    assert result["overall_status"] == "unknown"


def test_empty_sources_produce_unknown_summary():
    result = assess_ioc_freshness([], now=NOW)
    assert result["overall_status"] == "unknown"
