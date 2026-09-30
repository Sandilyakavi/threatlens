from threatlens.collectors.feodo import parse_feed
from threatlens.models.ioc import IOCType


def test_parse_feodo_record():
    records = [
        {
            "ip_address": "192.0.2.10",
            "port": 8080,
            "status": "offline",
            "hostname": None,
            "as_number": 14061,
            "as_name": "TEST-ASN",
            "country": "US",
            "first_seen": "2026-01-01 12:00:00",
            "last_online": "2026-01-02",
            "malware": "TestMalware",
        }
    ]

    iocs = parse_feed(records)

    assert len(iocs) == 1

    ioc = iocs[0]

    assert ioc.value == "192.0.2.10"
    assert ioc.ioc_type == IOCType.IP
    assert ioc.source == "feodo-tracker"
    assert ioc.threat_type == "TestMalware"
    assert "testmalware" in ioc.tags
    assert "asn:14061" in ioc.tags
    assert "country:us" in ioc.tags
