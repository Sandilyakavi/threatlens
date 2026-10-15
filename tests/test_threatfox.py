
import pytest
import requests

from threatlens.collectors import ingest as ingestion
from threatlens.collectors.threatfox import fetch_feed, parse_feed
from threatlens.database.ioc_repository import IOCRepository
from threatlens.models.ioc import IOC, IOCType


def test_parse_threatfox_ip_port_record():
    records = [
        {
            "ioc": "192.0.2.10:8080",
            "ioc_type": "ip:port",
            "malware": "TestMalware",
            "confidence_level": 85,
            "first_seen": "2026-01-01 12:00:00",
            "last_seen": None,
        }
    ]

    iocs = parse_feed(records)

    assert len(iocs) == 1
    assert iocs[0].value == "192.0.2.10:8080"
    assert iocs[0].ioc_type == IOCType.IP_PORT
    assert iocs[0].source == "threatfox"
    assert iocs[0].confidence == 85
    assert iocs[0].threat_type == "TestMalware"
    assert "threatfox" in iocs[0].tags


def test_skip_unsupported_indicator_type():
    records = [
        {
            "ioc": "example.test",
            "ioc_type": "unsupported-type",
            "malware": "TestMalware",
        }
    ]

    assert parse_feed(records) == []


def test_parse_record_without_optional_fields():
    iocs = parse_feed([{"ioc": "example.test", "ioc_type": "domain"}])

    assert len(iocs) == 1
    assert iocs[0].ioc_type == IOCType.DOMAIN
    assert iocs[0].confidence == 0
    assert iocs[0].first_seen is None


def test_fetch_feed_success(monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "test-key")

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "query_status": "ok",
                "data": [{"ioc": "192.0.2.10"}],
            }

    def mock_post(url, **kwargs):
        assert kwargs["headers"]["Auth-Key"] == "test-key"
        assert kwargs["json"] == {"query": "get_iocs", "days": 1}
        return MockResponse()

    monkeypatch.setattr(
        "threatlens.collectors.threatfox.requests.post", mock_post
    )

    assert fetch_feed() == [{"ioc": "192.0.2.10"}]


def test_fetch_feed_requires_auth_key(monkeypatch):
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)
    monkeypatch.setattr(
        "threatlens.collectors.threatfox.load_dotenv", lambda: None
    )

    with pytest.raises(ValueError, match="not configured"):
        fetch_feed()


def test_fetch_feed_returns_empty_when_no_results(monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "test-key")

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"query_status": "no_result", "data": None}

    monkeypatch.setattr(
        "threatlens.collectors.threatfox.requests.post",
        lambda *args, **kwargs: MockResponse(),
    )

    assert fetch_feed() == []


def test_fetch_feed_rejects_invalid_days():
    with pytest.raises(ValueError, match="days"):
        fetch_feed(days=8)


def test_fetch_feed_handles_http_error(monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "test-key")

    def mock_post(*args, **kwargs):
        raise requests.HTTPError("Unauthorized")

    monkeypatch.setattr(
        "threatlens.collectors.threatfox.requests.post", mock_post
    )

    with pytest.raises(requests.HTTPError):
        fetch_feed()


def test_ingest_threatfox_stores_records(monkeypatch, tmp_path):
    database_path = tmp_path / "test.db"

    monkeypatch.setattr(
        ingestion,
        "fetch_threatfox_feed",
        lambda days=1: [{"ioc": "192.0.2.25"}],
    )
    monkeypatch.setattr(
        ingestion,
        "parse_threatfox_feed",
        lambda records: [
            IOC(
                value="192.0.2.25",
                ioc_type=IOCType.IP,
                source="threatfox",
                confidence=90,
            )
        ],
    )

    result = ingestion.ingest_threatfox(database_path=database_path)

    assert result.feed == "threatfox"
    assert result.fetched == 1
    assert result.parsed == 1
    assert result.new == 1
    assert result.existing == 0
    assert result.skipped == 0
    assert IOCRepository(database_path).count() == 1
