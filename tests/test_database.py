
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
