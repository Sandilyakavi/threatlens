from threatlens.database.schema import initialize_database
from threatlens.database.ioc_repository import IOCRepository
from threatlens.models.ioc import IOC, IOCType, ThreatLevel


def test_add_and_find_ioc():
    initialize_database()

    repository = IOCRepository()

    ioc = IOC(
        value="198.51.100.10",
        ioc_type=IOCType.IP,
        source="test-feed",
        confidence=85,
        threat_level=ThreatLevel.HIGH,
    )

    ioc_id = repository.add(ioc)

    assert ioc_id > 0

    result = repository.find_by_value("198.51.100.10")

    assert result is not None
    assert result["value"] == "198.51.100.10"
    assert result["ioc_type"] == "ip"
    assert result["source"] == "test-feed"
    assert result["confidence"] == 85
    assert result["threat_level"] == "high"


def test_ioc_count():
    initialize_database()

    repository = IOCRepository()

    assert repository.count() >= 1
