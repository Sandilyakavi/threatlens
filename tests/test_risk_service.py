
import json

import pytest

from threatlens.database.schema import initialize_database
from threatlens.database.ioc_repository import IOCRepository
from threatlens.detection.risk_service import RiskService
from threatlens.models.ioc import IOC, IOCType


@pytest.fixture
def repository(tmp_path):
    database_path = tmp_path / "test_threatlens.db"
    initialize_database(database_path)
    return IOCRepository(database_path)


def test_assess_returns_none_for_unknown_ioc(repository):
    service = RiskService(repository.database_path)

    assert service.assess("192.0.2.10", "ip") is None


def test_assess_uses_stored_ioc_evidence(repository):
    ioc = IOC(
        value="198.51.100.20",
        ioc_type=IOCType.IP,
        source="test-feed",
        confidence=85,
        threat_type="botnet",
        tags=["c2"],
    )
    repository.add(ioc)

    service = RiskService(repository.database_path)
    result = service.assess("198.51.100.20", "ip")

    assert result is not None
    assert result.score == 64
    assert result.level == "high"
    assert any("85/100" in reason for reason in result.reasons)
    assert any("botnet" in reason for reason in result.reasons)


def test_assess_uses_distinct_source_count(repository):
    ioc = IOC(
        value="203.0.113.15",
        ioc_type=IOCType.IP,
        source="feed-one",
        confidence=50,
    )
    repository.add(ioc)
    repository.add(
        IOC(
            value=ioc.value,
            ioc_type=ioc.ioc_type,
            source="feed-two",
            confidence=50,
        )
    )

    service = RiskService(repository.database_path)
    result = service.assess(ioc.value, "ip")

    assert result is not None
    assert result.score == 35
    assert any("2 distinct sources" in reason for reason in result.reasons)


def test_assess_distinguishes_ioc_types(repository):
    repository.add(
        IOC(
            value="same.example",
            ioc_type=IOCType.DOMAIN,
            source="test-feed",
            confidence=80,
        )
    )
    repository.add(
        IOC(
            value="same.example",
            ioc_type=IOCType.URL,
            source="test-feed",
            confidence=20,
        )
    )

    service = RiskService(repository.database_path)

    domain_result = service.assess("same.example", "domain")
    url_result = service.assess("same.example", "url")

    assert domain_result is not None
    assert url_result is not None
    assert domain_result.score == 32
    assert url_result.score == 8


def test_assess_handles_invalid_source_metadata(repository):
    ioc = IOC(
        value="192.0.2.50",
        ioc_type=IOCType.IP,
        source="test-feed",
        confidence=50,
    )
    repository.add(ioc)

    service = RiskService(repository.database_path)
    result = service.assess(ioc.value, "ip")

    assert result is not None
    assert result.score == 20
    assert result.level == "low"
