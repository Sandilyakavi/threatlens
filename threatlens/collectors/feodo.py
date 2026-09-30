import requests
from datetime import datetime

from threatlens.models.ioc import IOC, IOCType


FEODO_BLOCKLIST_URL = (
    "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
)


def fetch_feed() -> list[dict]:
    """Fetch the current Feodo Tracker IP blocklist."""

    response = requests.get(
        FEODO_BLOCKLIST_URL,
        timeout=15,
    )

    response.raise_for_status()

    data = response.json()

    if not isinstance(data, list):
        raise ValueError("Unexpected Feodo Tracker response format")

    return data


def parse_feed(records: list[dict]) -> list[IOC]:
    """Convert Feodo Tracker records into ThreatLens IOC objects."""

    iocs = []

    for record in records:
        ip_address = record.get("ip_address")

        if not ip_address:
            continue

        first_seen = _parse_datetime(record.get("first_seen"))

        last_online = record.get("last_online")
        last_seen = _parse_date(last_online)

        malware = record.get("malware")
        as_number = record.get("as_number")
        country = record.get("country")

        tags = ["c2"]

        if malware:
            tags.append(malware.lower())

        if as_number:
            tags.append(f"asn:{as_number}")

        if country:
            tags.append(f"country:{country.lower()}")

        ioc = IOC(
            value=ip_address,
            ioc_type=IOCType.IP,
            source="feodo-tracker",
            threat_type=malware,
            first_seen=first_seen,
            last_seen=last_seen,
            tags=tags,
        )

        iocs.append(ioc)

    return iocs


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    return datetime.fromisoformat(value)


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None

    return datetime.strptime(value, "%Y-%m-%d")
