"""Safe maintenance operations for ThreatLens source evidence."""

import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from threatlens.collectors.threatfox import _parse_datetime, fetch_feed
from threatlens.database.connection import DATABASE_PATH


def backfill_threatfox(
    database_path: Path = DATABASE_PATH,
    *,
    dry_run: bool = True,
    days: int = 7,
    feed_fetcher: Callable[..., list[dict]] = fetch_feed,
) -> dict:
    """Repair missing ThreatFox timestamps using exact IOC matches.

    Dry-run is the default. Existing non-empty timestamps are never replaced.
    Unmatched or invalid feed records are reported and skipped.
    """
    if not 1 <= days <= 7:
        raise ValueError("days must be between 1 and 7")

    database_path = Path(database_path).resolve()
    if not database_path.is_file():
        raise FileNotFoundError(f"Database not found: {database_path}")

    records = feed_fetcher(days=days)
    api_by_ioc = {
        record["ioc"]: record
        for record in records
        if isinstance(record, dict)
        and isinstance(record.get("ioc"), str)
        and record["ioc"]
    }

    with sqlite3.connect(database_path, timeout=30) as connection:
        rows = connection.execute("""
            SELECT i.id, i.value,
                   s.source_first_seen, s.source_last_seen
            FROM ioc_sources AS s
            JOIN iocs AS i ON i.id = s.ioc_id
            WHERE s.source_name = 'threatfox'
              AND (
                  s.source_first_seen IS NULL
                  OR TRIM(s.source_first_seen) = ''
                  OR s.source_last_seen IS NULL
                  OR TRIM(s.source_last_seen) = ''
              )
            ORDER BY i.id
        """).fetchall()

    stats = Counter()
    plan = []

    for ioc_id, value, old_first, old_last in rows:
        record = api_by_ioc.get(value)
        if record is None:
            stats["unmatched"] += 1
            continue

        first_missing = not (old_first and old_first.strip())
        last_missing = not (old_last and old_last.strip())

        parsed_first = _parse_datetime(record.get("first_seen"))
        parsed_last = _parse_datetime(record.get("last_seen"))

        new_first = None
        new_last = None

        if first_missing:
            if parsed_first is None:
                stats["invalid_first_seen"] += 1
                continue
            new_first = parsed_first.isoformat()

        if last_missing and parsed_last is not None:
            new_last = parsed_last.isoformat()

        if new_first or new_last:
            plan.append((ioc_id, new_first, new_last))
            if new_first:
                stats["first_seen_to_fill"] += 1
            if new_last:
                stats["last_seen_to_fill"] += 1
        else:
            stats["no_usable_timestamp"] += 1

    result = {
        "dry_run": dry_run,
        "records_examined": len(rows),
        "records_to_update": len(plan),
        "first_seen_to_fill": stats["first_seen_to_fill"],
        "last_seen_to_fill": stats["last_seen_to_fill"],
        "unmatched": stats["unmatched"],
        "invalid_first_seen": stats["invalid_first_seen"],
        "no_usable_timestamp": stats["no_usable_timestamp"],
        "updated_records": 0,
        "backup_path": None,
    }

    if dry_run or not plan:
        return result

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = database_path.with_name(
        f"{database_path.stem}.pre-threatfox-backfill-{stamp}"
        f"{database_path.suffix}"
    )
    if backup_path.exists():
        raise FileExistsError(f"Backup already exists: {backup_path}")

    # SQLite's backup API makes a consistent snapshot.
    with sqlite3.connect(backup_path) as backup:
        with sqlite3.connect(database_path, timeout=30) as source:
            source.backup(backup)

    updated = 0
    try:
        with sqlite3.connect(database_path, timeout=30) as connection:
            connection.execute("PRAGMA busy_timeout = 30000")
            connection.execute("BEGIN IMMEDIATE")

            for ioc_id, new_first, new_last in plan:
                cursor = connection.execute("""
                    UPDATE ioc_sources
                    SET source_first_seen = COALESCE(
                            NULLIF(TRIM(source_first_seen), ''),
                            ?
                        ),
                        source_last_seen = COALESCE(
                            NULLIF(TRIM(source_last_seen), ''),
                            ?
                        )
                    WHERE ioc_id = ?
                      AND source_name = 'threatfox'
                """, (new_first, new_last, ioc_id))
                updated += cursor.rowcount

            remaining = connection.execute("""
                SELECT COUNT(*)
                FROM ioc_sources
                WHERE source_name = 'threatfox'
                  AND (
                      source_first_seen IS NULL
                      OR TRIM(source_first_seen) = ''
                  )
            """).fetchone()[0]

            expected = connection.execute("""
                SELECT COUNT(*)
                FROM ioc_sources
                WHERE source_name = 'threatfox'
            """).fetchone()[0]

            if updated != len(plan):
                raise RuntimeError(
                    f"Update count mismatch: expected {len(plan)}, "
                    f"updated {updated}"
                )

            connection.commit()

    except Exception:
        # The connection context rolls back an uncommitted transaction.
        raise

    result["updated_records"] = updated
    result["backup_path"] = str(backup_path)
    result["remaining_missing_first_seen"] = remaining
    result["source_records_total"] = expected
    return result
