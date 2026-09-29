from threatlens.database.connection import get_connection
from threatlens.models.ioc import IOC


class IOCRepository:
    """Database operations for ThreatLens IOCs."""

    def add(self, ioc: IOC) -> int:
        """Insert an IOC and return its database ID."""

        connection = get_connection()

        cursor = connection.execute(
            """
            INSERT INTO iocs (
                value,
                ioc_type,
                source,
                confidence,
                threat_level,
                threat_type,
                first_seen,
                last_seen,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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

        connection.commit()
        ioc_id = cursor.lastrowid
        connection.close()

        return ioc_id

    def find_by_value(self, value: str) -> dict | None:
        """Find an IOC by its exact indicator value."""

        connection = get_connection()

        row = connection.execute(
            """
            SELECT *
            FROM iocs
            WHERE value = ?
            LIMIT 1
            """,
            (value,),
        ).fetchone()

        connection.close()

        return dict(row) if row else None

    def count(self) -> int:
        """Return the total number of stored IOCs."""

        connection = get_connection()

        row = connection.execute(
            "SELECT COUNT(*) AS count FROM iocs"
        ).fetchone()

        connection.close()

        return row["count"]
