
from pathlib import Path

from threatlens.database.connection import get_connection


def initialize_database(database_path: Path | None = None) -> None:
    """Create the ThreatLens database schema."""

    if database_path is None:
        connection = get_connection()
    else:
        connection = get_connection(database_path)

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence INTEGER NOT NULL DEFAULT 0,
            threat_level TEXT NOT NULL DEFAULT 'low',
            threat_type TEXT,
            first_seen TEXT,
            last_seen TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(value, ioc_type)
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS ioc_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_id INTEGER NOT NULL,
            source_name TEXT NOT NULL,
            source_first_seen TEXT,
            source_last_seen TEXT,
            source_metadata TEXT,
            collected_at TEXT NOT NULL,
            FOREIGN KEY (ioc_id) REFERENCES iocs(id)
                ON DELETE CASCADE,
            UNIQUE(ioc_id, source_name)
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_iocs_value
        ON iocs(value)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_iocs_type
        ON iocs(ioc_type)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ioc_sources_source
        ON ioc_sources(source_name)
        """
    )

    connection.commit()
    connection.close()
