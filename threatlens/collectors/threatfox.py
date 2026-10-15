import os

import requests
from dotenv import load_dotenv
from datetime import datetime

from threatlens.models.ioc import IOC, IOCType

def parse_feed(records: list[dict]) -> list[IOC]:
    """Convert ThreatFox API records into ThreatLens IOC objects."""

    iocs = []

    for record in records:
        indicator = record.get("ioc")
        indicator_type = record.get("ioc_type")

        if not indicator or not indicator_type:
            continue

        threat_type = record.get("malware")
        first_seen = _parse_datetime(record.get("first_seen"))
        last_seen = _parse_datetime(record.get("last_seen"))

        tags = ["threatfox"]

        if threat_type:
            tags.append(threat_type.lower())

        confidence = record.get("confidence_level", 0)

        try:
            confidence = int(confidence)
        except (TypeError, ValueError):
            confidence = 0

        if indicator_type == "ip:port":
            ioc_type = IOCType.IP_PORT
        elif indicator_type == "domain":
            ioc_type = IOCType.DOMAIN
        elif indicator_type == "url":
            ioc_type = IOCType.URL
        elif indicator_type == "md5_hash":
            ioc_type = IOCType.HASH_MD5
        elif indicator_type == "sha1_hash":
            ioc_type = IOCType.HASH_SHA1
        elif indicator_type == "sha256_hash":
            ioc_type = IOCType.HASH_SHA256
        elif indicator_type == "ip":
            ioc_type = IOCType.IP
        else:
            continue

        iocs.append(
            IOC(
                value=indicator,
                ioc_type=ioc_type,
                source="threatfox",
                confidence=confidence,
                threat_type=threat_type,
                first_seen=first_seen,
                last_seen=last_seen,
                tags=tags,
            )
        )

    return iocs


def _parse_datetime(value: str | None) -> datetime | None:
    """Parse an optional ISO-format timestamp."""

    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

def fetch_feed(days: int = 1) -> list[dict]:
    """Fetch recent IOCs from the ThreatFox API."""

    if not 1 <= days <= 7:
        raise ValueError("days must be between 1 and 7")

    load_dotenv()

    auth_key = os.getenv("THREATFOX_AUTH_KEY")

    if not auth_key or auth_key == "PASTE_YOUR_AUTH_KEY_HERE":
        raise ValueError(
            "THREATFOX_AUTH_KEY is not configured in .env"
        )

    response = requests.post(
        THREATFOX_API_URL,
        headers={
            "Auth-Key": auth_key,
            "Content-Type": "application/json",
        },
        json={
            "query": "get_iocs",
            "days": days,
        },
        timeout=20,
    )

    response.raise_for_status()
    result = response.json()

    if not isinstance(result, dict):
        raise ValueError("Unexpected ThreatFox API response")

    status = result.get("query_status")

    if status == "no_result":
        return []

    if status != "ok":
        raise ValueError(
            f"ThreatFox API returned status: {status}"
        )

    records = result.get("data")

    if not isinstance(records, list):
        raise ValueError("Unexpected ThreatFox data format")

    return records
