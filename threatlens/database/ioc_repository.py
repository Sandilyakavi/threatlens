
import json
from datetime import datetime, timezone
from pathlib import Path

from threatlens.database.connection import DATABASE_PATH, get_connection
from threatlens.models.ioc import IOC


class IOCRepository:
    """Database operations for ThreatLens IOCs and their sources."""

    def __init__(self, database_path: Path = DATABASE_PATH):
        self.database_path = database_path

    def add_with_status(self, ioc: IOC) -> tuple[int, bool]:
        """Store an IOC and its source; return (IOC ID, is_new)."""

        connection = get_connection(self.database_path)

        try:
            cursor = connection.execute(
                """
                INSERT INTO iocs (
                    value, ioc_type, source, confidence, threat_level,
                    threat_type, first_seen, last_seen, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(value, ioc_type) DO NOTHING
                """,
                (
                    ioc.value,
                    ioc.ioc_type.value,
                    ioc.source,
                    ioc.confidence,
                    ioc.threat_level.value,
                    ioc.threat_type,
                    ioc.first_seen.isoformat() if ioc.first_seen else None,
                    ioc.last_seen.isoformat() if ioc.last_seen else None,
                    ioc.created_at.isoformat(),
                ),
            )

            is_new = cursor.rowcount == 1

            row = connection.execute(
                """
                SELECT id FROM iocs
                WHERE value = ? AND ioc_type = ?
                """,
                (ioc.value, ioc.ioc_type.value),
            ).fetchone()

            if row is None:
                raise RuntimeError("IOC missing after insert attempt")

            ioc_id = row["id"]

            metadata = json.dumps({
                "threat_type": ioc.threat_type,
                "tags": ioc.tags,
            })

            now = datetime.now(timezone.utc).isoformat()

            connection.execute(
                """
                INSERT INTO ioc_sources (
                    ioc_id, source_name, source_first_seen,
                    source_last_seen, source_metadata, collected_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_id, source_name) DO UPDATE SET
                    source_first_seen = COALESCE(
                        excluded.source_first_seen,
                        ioc_sources.source_first_seen
                    ),
                    source_last_seen = COALESCE(
                        excluded.source_last_seen,
                        ioc_sources.source_last_seen
                    ),
                    source_metadata = excluded.source_metadata,
                    collected_at = excluded.collected_at
                """,
                (
                    ioc_id,
                    ioc.source,
                    ioc.first_seen.isoformat() if ioc.first_seen else None,
                    ioc.last_seen.isoformat() if ioc.last_seen else None,
                    metadata,
                    now,
                ),
            )

            connection.commit()
            return ioc_id, is_new

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def add(self, ioc: IOC) -> int:
        """Insert or reuse an IOC and return its ID."""

        ioc_id, _ = self.add_with_status(ioc)
        return ioc_id

    def find_by_value(self, value: str) -> dict | None:
        """Find an IOC by its exact indicator value."""

        connection = get_connection(self.database_path)

        try:
            row = connection.execute(
                """
                SELECT * FROM iocs
                WHERE value = ?
                LIMIT 1
                """,
                (value,),
            ).fetchone()

            return dict(row) if row else None

        finally:
            connection.close()

    def count(self) -> int:
        """Return the total number of unique IOCs."""

        connection = get_connection(self.database_path)

        try:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM iocs"
            ).fetchone()

            return row["count"]

        finally:
            connection.close()

    def get_sources(self, value: str) -> list[dict]:
        """Return all intelligence sources associated with an IOC."""

        connection = get_connection(self.database_path)

        try:
            rows = connection.execute(
                """
                SELECT
                    s.source_name,
                    s.source_first_seen,
                    s.source_last_seen,
                    s.source_metadata,
                    s.collected_at
                FROM ioc_sources AS s
                JOIN iocs AS i ON i.id = s.ioc_id
                WHERE i.value = ?
                ORDER BY s.source_name
                """,
                (value,),
            ).fetchall()

            return [dict(row) for row in rows]

        finally:
            connection.close()
