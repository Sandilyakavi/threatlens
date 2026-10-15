
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


    def get_sources(
        self,
        value: str,
        ioc_type: str | None = None,
    ) -> list[dict]:
        """Return intelligence sources associated with an IOC."""

        connection = get_connection(self.database_path)

        try:
            query = """
                SELECT
                    s.source_name,
                    s.source_first_seen,
                    s.source_last_seen,
                    s.source_metadata,
                    s.collected_at
                FROM ioc_sources AS s
                JOIN iocs AS i ON i.id = s.ioc_id
                WHERE i.value = ?
            """
            params: tuple = (value,)

            if ioc_type is not None:
                query += " AND i.ioc_type = ?"
                params += (ioc_type,)

            query += " ORDER BY s.source_name"

            rows = connection.execute(query, params).fetchall()
            return [dict(row) for row in rows]

        finally:
            connection.close()

    def get_correlation(
        self,
        value: str,
        ioc_type: str | None = None,
    ) -> dict | None:
        """Return an IOC with its source count and source evidence."""

        connection = get_connection(self.database_path)

        try:
            query = """
                SELECT
                    i.*,
                    COUNT(DISTINCT s.source_name) AS source_count
                FROM iocs AS i
                LEFT JOIN ioc_sources AS s ON s.ioc_id = i.id
                WHERE i.value = ?
            """
            params: tuple = (value,)

            if ioc_type is not None:
                query += " AND i.ioc_type = ?"
                params += (ioc_type,)

            query += " GROUP BY i.id ORDER BY i.id LIMIT 1"

            row = connection.execute(query, params).fetchone()

            if row is None:
                return None

            result = dict(row)
            result["sources"] = self.get_sources(
                value,
                result["ioc_type"],
            )
            result["is_multi_source"] = result["source_count"] > 1

            return result

        finally:
            connection.close()

    def get_multi_source_iocs(self, min_sources: int = 2) -> list[dict]:
        """List IOCs observed by at least min_sources distinct sources."""

        if min_sources < 2:
            raise ValueError("min_sources must be at least 2")

        connection = get_connection(self.database_path)

        try:
            rows = connection.execute(
                """
                SELECT
                    i.*,
                    COUNT(DISTINCT s.source_name) AS source_count,
                    GROUP_CONCAT(
                        DISTINCT s.source_name
                    ) AS source_names
                FROM iocs AS i
                JOIN ioc_sources AS s ON s.ioc_id = i.id
                GROUP BY i.id
                HAVING COUNT(DISTINCT s.source_name) >= ?
                ORDER BY source_count DESC, i.value ASC
                """,
                (min_sources,),
            ).fetchall()

            return [dict(row) for row in rows]

        finally:
            connection.close()



    def get_correlation(self, value: str) -> dict | None:
        """Return an IOC with its source count and source evidence."""

        connection = get_connection(self.database_path)

        try:
            row = connection.execute(
                """
                SELECT
                    i.*,
                    COUNT(s.id) AS source_count
                FROM iocs AS i
                LEFT JOIN ioc_sources AS s ON s.ioc_id = i.id
                WHERE i.value = ?
                GROUP BY i.id
                LIMIT 1
                """,
                (value,),
            ).fetchone()

            if row is None:
                return None

            result = dict(row)
            result["sources"] = self.get_sources(value)
            result["is_multi_source"] = result["source_count"] > 1

            return result

        finally:
            connection.close()
