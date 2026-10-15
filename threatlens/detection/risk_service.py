
import json
from pathlib import Path

from threatlens.database.connection import DATABASE_PATH
from threatlens.database.ioc_repository import IOCRepository
from threatlens.detection.risk_scorer import RiskAssessment, assess_risk


class RiskService:
    """Assess IOC risk using evidence stored in ThreatLens."""

    def __init__(self, database_path: Path = DATABASE_PATH):
        self.repository = IOCRepository(database_path)

    def assess(
        self,
        value: str,
        ioc_type: str | None = None,
    ) -> RiskAssessment | None:
        """Return an explainable risk assessment, or None if not found."""

        record = self.repository.get_correlation(value, ioc_type)

        if record is None:
            return None

        tags: set[str] = set()
        threat_types: set[str] = set()

        if record.get("threat_type"):
            threat_types.add(str(record["threat_type"]).strip())

        for source in record.get("sources", []):
            metadata = source.get("source_metadata")

            if not metadata:
                continue

            try:
                if isinstance(metadata, str):
                    metadata = json.loads(metadata)
            except (json.JSONDecodeError, TypeError):
                continue

            if not isinstance(metadata, dict):
                continue

            threat_type = metadata.get("threat_type")
            if isinstance(threat_type, str) and threat_type.strip():
                threat_types.add(threat_type.strip())

            source_tags = metadata.get("tags", [])
            if isinstance(source_tags, list):
                tags.update(
                    tag.strip()
                    for tag in source_tags
                    if isinstance(tag, str) and tag.strip()
                )

        # Prefer the IOC's own threat type; use source metadata as fallback.
        threat_type = record.get("threat_type")
        if not threat_type and threat_types:
            threat_type = sorted(threat_types)[0]

        return assess_risk(
            confidence=int(record.get("confidence") or 0),
            source_count=max(int(record.get("source_count") or 0), 1),
            threat_type=threat_type,
            tags=sorted(tags),
        )
