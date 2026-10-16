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

            incoming_metadata = {
                "threat_type": ioc.threat_type,
                "tags": ioc.tags,
            }

            existing_source = connection.execute(
                """
                SELECT source_first_seen, source_last_seen, source_metadata
                FROM ioc_sources
                WHERE ioc_id = ? AND source_name = ?
                """,
                (ioc_id, ioc.source),
            ).fetchone()

            existing_metadata = {}
            if existing_source and existing_source["source_metadata"]:
                try:
                    parsed = json.loads(existing_source["source_metadata"])
                    if isinstance(parsed, dict):
                        existing_metadata = parsed
                except (json.JSONDecodeError, TypeError):
                    pass

            # Keep existing non-empty fields when incoming data is absent.
            metadata = {
                key: value
                for key, value in existing_metadata.items()
                if value is not None and value != "" and value != []
            }

            for key, value in incoming_metadata.items():
                if value is not None and value != "" and value != []:
                    metadata[key] = value

            # Accumulate tags while filtering malformed values and duplicates.
            old_tags = existing_metadata.get("tags", [])
            new_tags = incoming_metadata.get("tags", [])
            if not isinstance(old_tags, list):
                old_tags = []
            if not isinstance(new_tags, list):
                new_tags = []

            metadata["tags"] = sorted({
                tag.strip()
                for tag in old_tags + new_tags
                if isinstance(tag, str) and tag.strip()
            })

            encoded_metadata = json.dumps(metadata)
            now = datetime.now(timezone.utc).isoformat()

            incoming_first_seen = (
                ioc.first_seen.isoformat() if ioc.first_seen else None
            )
            incoming_last_seen = (
                ioc.last_seen.isoformat() if ioc.last_seen else None
            )

            previous_evidence = None
            if existing_source is not None:
                previous_evidence = {
                    "first_seen": existing_source["source_first_seen"],
                    "last_seen": existing_source["source_last_seen"],
                    "metadata": existing_metadata,
                }

            current_evidence = {
                "first_seen": (
                    incoming_first_seen
                    if incoming_first_seen is not None
                    else (
                        existing_source["source_first_seen"]
                        if existing_source is not None
                        else None
                    )
                ),
                "last_seen": (
                    incoming_last_seen
                    if incoming_last_seen is not None
                    else (
                        existing_source["source_last_seen"]
                        if existing_source is not None
                        else None
                    )
                ),
                "metadata": metadata,
            }

            event_type = None
            if existing_source is None:
                event_type = "source_added"
            elif previous_evidence != current_evidence:
                event_type = "evidence_updated"

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
                    incoming_first_seen,
                    incoming_last_seen,
                    encoded_metadata,
                    now,
                ),
            )

            if event_type is not None:
                connection.execute(
                    """
                    INSERT INTO ioc_evidence_history (
                        ioc_id, source_name, event_type,
                        previous_evidence, current_evidence, recorded_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ioc_id,
                        ioc.source,
                        event_type,
                        (
                            json.dumps(previous_evidence, sort_keys=True)
                            if previous_evidence is not None
                            else None
                        ),
                        json.dumps(current_evidence, sort_keys=True),
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

    def find_types_by_value(self, value: str) -> list[str]:
        """Return all distinct IOC types stored for a value."""

        connection = get_connection(self.database_path)

        try:
            rows = connection.execute(
                """
                SELECT DISTINCT ioc_type
                FROM iocs
                WHERE value = ?
                ORDER BY ioc_type
                """,
                (value,),
            ).fetchall()

            return [row["ioc_type"] for row in rows]

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

    def find_by_value_and_type(
        self,
        value: str,
        ioc_type: str,
    ) -> dict | None:
        """Find an IOC by its exact value and type."""

        connection = get_connection(self.database_path)

        try:
            row = connection.execute(
                """
                SELECT *
                FROM iocs
                WHERE value = ? AND ioc_type = ?
                LIMIT 1
                """,
                (value, ioc_type),
            ).fetchone()

            return dict(row) if row is not None else None

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

    def get_evidence_history(
        self,
        value: str,
        ioc_type: str | None = None,
    ) -> list[dict]:
        """Return recorded evidence changes for an IOC, oldest first."""

        connection = get_connection(self.database_path)
        try:
            query = """
                SELECT
                    h.id,
                    i.value,
                    i.ioc_type,
                    h.source_name,
                    h.event_type,
                    h.previous_evidence,
                    h.current_evidence,
                    h.recorded_at
                FROM ioc_evidence_history AS h
                JOIN iocs AS i ON i.id = h.ioc_id
                WHERE i.value = ?
            """
            params: tuple = (value,)

            if ioc_type is not None:
                query += " AND i.ioc_type = ?"
                params += (ioc_type,)

            query += " ORDER BY h.id ASC"
            rows = connection.execute(query, params).fetchall()

            history = []
            for row in rows:
                item = dict(row)
                item["previous_evidence"] = (
                    json.loads(item["previous_evidence"])
                    if item["previous_evidence"] is not None
                    else None
                )
                item["current_evidence"] = json.loads(
                    item["current_evidence"]
                )
                history.append(item)

            return history
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
