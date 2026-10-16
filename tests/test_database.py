import pytest
from threatlens.models.ioc import IOC, IOCType
from threatlens.database.schema import initialize_database
from threatlens.database.ioc_repository import IOCRepository
from threatlens.models.ioc import IOC, IOCType, ThreatLevel


def make_ioc(source: str) -> IOC:
    """Create a reusable test IOC."""

    return IOC(
        value="198.51.100.10",
        ioc_type=IOCType.IP,
        source=source,
        confidence=85,
        threat_level=ThreatLevel.HIGH,
        threat_type="test-malware",
        tags=["c2", "test"],
    )


def test_add_and_find_ioc(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)

    repository = IOCRepository(database_path)
    ioc = make_ioc("test-feed")

    ioc_id = repository.add(ioc)
    result = repository.find_by_value("198.51.100.10")

    assert ioc_id > 0
    assert result is not None
    assert result["value"] == "198.51.100.10"
    assert result["ioc_type"] == "ip"
    assert result["source"] == "test-feed"
    assert result["confidence"] == 85
    assert result["threat_level"] == "high"


def test_ioc_count(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)

    repository = IOCRepository(database_path)

    assert repository.count() == 0


def test_duplicate_ioc_is_not_inserted(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)

    repository = IOCRepository(database_path)
    ioc = make_ioc("test-feed")

    first_id = repository.add(ioc)
    second_id = repository.add(ioc)

    assert first_id == second_id
    assert repository.count() == 1


def test_same_source_is_recorded_once(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)

    repository = IOCRepository(database_path)
    ioc = make_ioc("feodo-tracker")

    repository.add(ioc)
    repository.add(ioc)

    sources = repository.get_sources(ioc.value)

    assert repository.count() == 1
    assert len(sources) == 1
    assert sources[0]["source_name"] == "feodo-tracker"


def test_same_ioc_can_have_multiple_sources(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)

    repository = IOCRepository(database_path)

    feodo_ioc = make_ioc("feodo-tracker")
    threatfox_ioc = make_ioc("threatfox")

    feodo_id = repository.add(feodo_ioc)
    threatfox_id = repository.add(threatfox_ioc)

    sources = repository.get_sources(feodo_ioc.value)
    source_names = {source["source_name"] for source in sources}

    assert feodo_id == threatfox_id
    assert repository.count() == 1
    assert len(sources) == 2
    assert source_names == {"feodo-tracker", "threatfox"}


def test_add_with_status_reports_new_ioc(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)

    repository = IOCRepository(database_path)
    ioc = make_ioc("feodo-tracker")

    ioc_id, is_new = repository.add_with_status(ioc)

    assert ioc_id > 0
    assert is_new is True


def test_add_with_status_reports_existing_ioc(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)

    repository = IOCRepository(database_path)
    ioc = make_ioc("feodo-tracker")

    first_id, first_is_new = repository.add_with_status(ioc)
    second_id, second_is_new = repository.add_with_status(ioc)

    assert first_id == second_id
    assert first_is_new is True
    assert second_is_new is False
    assert repository.count() == 1

def test_correlation_identifies_multiple_sources(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    repository.add(make_ioc("feodo-tracker"))
    repository.add(make_ioc("threatfox"))

    result = repository.get_correlation("198.51.100.10")

    assert result is not None
    assert result["source_count"] == 2
    assert result["is_multi_source"] is True

    source_names = {source["source_name"] for source in result["sources"]}
    assert source_names == {"feodo-tracker", "threatfox"}


def test_correlation_returns_none_for_unknown_ioc(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    assert repository.get_correlation("203.0.113.99") is None

def test_multi_source_iocs_returns_only_correlated_indicators(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    repository.add(make_ioc("feodo-tracker"))
    repository.add(make_ioc("threatfox"))

    single_source = IOC(
        value="203.0.113.50",
        ioc_type=IOCType.IP,
        source="feodo-tracker",
    )
    repository.add(single_source)

    results = repository.get_multi_source_iocs()

    assert len(results) == 1
    assert results[0]["value"] == "198.51.100.10"
    assert results[0]["source_count"] == 2
    assert set(results[0]["source_names"].split(",")) == {
        "feodo-tracker",
        "threatfox",
    }


def test_multi_source_iocs_supports_minimum_source_count(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    repository.add(make_ioc("feodo-tracker"))
    repository.add(make_ioc("threatfox"))
    repository.add(make_ioc("another-feed"))

    assert len(repository.get_multi_source_iocs(min_sources=3)) == 1
    assert repository.get_multi_source_iocs(min_sources=4) == []


def test_multi_source_iocs_rejects_invalid_minimum(tmp_path):
    database_path = tmp_path / "test.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    with pytest.raises(ValueError, match="at least 2"):
        repository.get_multi_source_iocs(min_sources=1)

def test_reingestion_preserves_existing_metadata_when_new_metadata_is_missing(
    tmp_path,
):
    import json
    from datetime import datetime, timezone

    database_path = tmp_path / "test.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    original = make_ioc("threatfox")
    original.first_seen = datetime(2026, 10, 10, tzinfo=timezone.utc)
    original.last_seen = datetime(2026, 10, 12, tzinfo=timezone.utc)
    repository.add(original)

    incomplete = make_ioc("threatfox")
    incomplete.threat_type = None
    incomplete.tags = []
    incomplete.first_seen = None
    incomplete.last_seen = None
    repository.add(incomplete)

    sources = repository.get_sources(original.value, original.ioc_type.value)
    assert len(sources) == 1

    source = sources[0]
    metadata = json.loads(source["source_metadata"])

    assert metadata["threat_type"] == "test-malware"
    assert set(metadata["tags"]) == {"c2", "test"}
    assert source["source_first_seen"] == original.first_seen.isoformat()
    assert source["source_last_seen"] == original.last_seen.isoformat()


def test_reingestion_accumulates_new_tags_without_duplicates(tmp_path):
    import json

    database_path = tmp_path / "test.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    original = make_ioc("threatfox")
    repository.add(original)

    updated = make_ioc("threatfox")
    updated.tags = ["c2", "new-tag"]
    repository.add(updated)

    sources = repository.get_sources(original.value, original.ioc_type.value)
    metadata = json.loads(sources[0]["source_metadata"])

    assert metadata["tags"] == ["c2", "new-tag", "test"]

def test_audit_history_records_source_added_and_ignores_unchanged_reingestion(
    tmp_path,
):
    repository = IOCRepository(tmp_path / "audit.db")
    initialize_database(tmp_path / "audit.db")
    ioc = make_ioc("test-feed")

    repository.add(ioc)
    repository.add(ioc)

    history = repository.get_evidence_history(ioc.value, ioc.ioc_type.value)
    assert len(history) == 1
    assert history[0]["event_type"] == "source_added"
    assert history[0]["previous_evidence"] is None
    assert history[0]["current_evidence"]["metadata"]["threat_type"] == (
        "test-malware"
    )
    assert history[0]["recorded_at"]


def test_audit_history_records_meaningful_metadata_update(tmp_path):
    database_path = tmp_path / "audit.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    original = make_ioc("test-feed")
    repository.add(original)

    updated = make_ioc("test-feed")
    updated.tags = ["c2", "new-tag"]
    repository.add(updated)

    history = repository.get_evidence_history(
        original.value, original.ioc_type.value
    )
    assert len(history) == 2
    event = history[-1]
    assert event["event_type"] == "evidence_updated"
    assert set(event["previous_evidence"]["metadata"]["tags"]) == {
        "c2", "test"
    }
    assert set(event["current_evidence"]["metadata"]["tags"]) == {
        "c2", "new-tag", "test"
    }


def test_audit_history_preserves_existing_evidence_when_incoming_fields_missing(
    tmp_path,
):
    database_path = tmp_path / "audit.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    original = make_ioc("test-feed")
    repository.add(original)

    incomplete = make_ioc("test-feed")
    incomplete.threat_type = None
    incomplete.tags = []
    incomplete.first_seen = None
    incomplete.last_seen = None
    repository.add(incomplete)

    history = repository.get_evidence_history(
        original.value, original.ioc_type.value
    )
    assert len(history) == 1
    assert history[0]["event_type"] == "source_added"


def test_audit_history_records_a_separate_source(tmp_path):
    database_path = tmp_path / "audit.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    repository.add(make_ioc("feed-one"))
    repository.add(make_ioc("feed-two"))

    history = repository.get_evidence_history(
        "198.51.100.10", "ip"
    )
    assert [event["event_type"] for event in history] == [
        "source_added", "source_added"
    ]
    assert {event["source_name"] for event in history} == {
        "feed-one", "feed-two"
    }


def test_audit_history_survives_repeated_database_initialization(tmp_path):
    from threatlens.database.connection import get_connection

    database_path = tmp_path / "audit_migration.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    repository.add(make_ioc("test-feed"))
    before = repository.get_evidence_history(
        "198.51.100.10", "ip"
    )
    assert len(before) == 1

    # Simulate application startup against an existing database.
    initialize_database(database_path)

    after = repository.get_evidence_history(
        "198.51.100.10", "ip"
    )
    assert len(after) == 1
    assert after[0]["event_type"] == "source_added"

    connection = get_connection(database_path)
    try:
        row = connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name = 'ioc_evidence_history'
            """
        ).fetchone()
        assert row is not None
    finally:
        connection.close()


def test_audit_insert_failure_rolls_back_ioc_and_source_changes(tmp_path):
    import sqlite3
    from threatlens.database.connection import get_connection

    database_path = tmp_path / "audit_rollback.db"
    initialize_database(database_path)
    repository = IOCRepository(database_path)

    connection = get_connection(database_path)
    try:
        connection.execute(
            """
            CREATE TRIGGER fail_audit_insert
            BEFORE INSERT ON ioc_evidence_history
            BEGIN
                SELECT RAISE(ABORT, 'forced audit failure');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(sqlite3.IntegrityError, match="forced audit failure"):
        repository.add(make_ioc("test-feed"))

    assert repository.count() == 0
    assert repository.get_sources("198.51.100.10", "ip") == []
    assert repository.get_evidence_history("198.51.100.10", "ip") == []
