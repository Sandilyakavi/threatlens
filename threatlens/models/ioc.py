from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IOC:
    value: str
    ioc_type: IOCType
    source: str

    confidence: int = 0
    threat_level: ThreatLevel = ThreatLevel.LOW

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    threat_type: str | None = None
    tags: list[str] = field(default_factory=list)

    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
