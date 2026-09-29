from threatlens.models.ioc import IOC, IOCType, ThreatLevel


def test_create_ip_ioc():
    ioc = IOC(
        value="192.0.2.10",
        ioc_type=IOCType.IP,
        source="test-feed",
        confidence=90,
        threat_level=ThreatLevel.HIGH,
    )

    assert ioc.value == "192.0.2.10"
    assert ioc.ioc_type == IOCType.IP
    assert ioc.source == "test-feed"
    assert ioc.confidence == 90
    assert ioc.threat_level == ThreatLevel.HIGH
