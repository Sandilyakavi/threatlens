import sqlite3
from datetime import datetime, timezone

from threatlens.database.schema import initialize_database
from threatlens.maintenance import backfill_threatfox


def make_database(path, records):
    initialize_database(path)

    with sqlite3.connect(path) as con:
        for index, record in enumerate(records, start=1):
            con.execute("""
                INSERT INTO iocs (
                    id, value, ioc_type, source, confidence,
                    threat_level, created_at
                )
                VALUES (?, ?, 'domain', 'threatfox', 50, 'low', ?)
            """, (
                index,
                record["ioc"],
                "2026-10-16T00:00:00+00:00",
            ))
            con.execute("""
                INSERT INTO ioc_sources (
                    ioc_id, source_name, source_first_seen,
                    source_last_seen, source_metadata, collected_at
                )
                VALUES (?, 'threatfox', ?, ?, '{}', ?)
            """, (
                index,
                record.get("stored_first"),
                record.get("stored_last"),
                "2026-10-16T00:00:00+00:00",
            ))


def fake_feed(records):
    def fetcher(*, days):
        assert days == 7
        return records
    return fetcher


def test_dry_run_does_not_modify_database(tmp_path):
    db = tmp_path / "test.db"
    feed = [{
        "ioc": "example.test",
        "first_seen": "2026-10-15 08:00:00 UTC",
        "last_seen": "2026-10-15 09:00:00 UTC",
    }]
    make_database(db, [{"ioc": "example.test"}])

    result = backfill_threatfox(
        db, dry_run=True, feed_fetcher=fake_feed(feed)
    )

    assert result["records_to_update"] == 1
    assert result["first_seen_to_fill"] == 1
    assert result["last_seen_to_fill"] == 1
    assert result["updated_records"] == 0
    with sqlite3.connect(db) as con:
        values = con.execute("""
            SELECT source_first_seen, source_last_seen
            FROM ioc_sources WHERE source_name = 'threatfox'
        """).fetchone()
    assert values == (None, None)


def test_apply_repairs_timestamps_and_creates_backup(tmp_path):
    db = tmp_path / "test.db"
    feed = [{
        "ioc": "example.test",
        "first_seen": "2026-10-15 08:00:00 UTC",
        "last_seen": "2026-10-15 09:00:00 UTC",
    }]
    make_database(db, [{"ioc": "example.test"}])

    result = backfill_threatfox(
        db, dry_run=False, feed_fetcher=fake_feed(feed)
    )

    assert result["updated_records"] == 1
    assert result["remaining_missing_first_seen"] == 0
    assert result["backup_path"]
    assert (tmp_path / result["backup_path"].split("/")[-1]).is_file()

    with sqlite3.connect(db) as con:
        values = con.execute("""
            SELECT source_first_seen, source_last_seen
            FROM ioc_sources WHERE source_name = 'threatfox'
        """).fetchone()
    assert values == (
        "2026-10-15T08:00:00+00:00",
        "2026-10-15T09:00:00+00:00",
    )


def test_existing_timestamps_are_never_overwritten(tmp_path):
    db = tmp_path / "test.db"
    make_database(db, [{
        "ioc": "example.test",
        "stored_last": "2026-10-14T10:00:00+00:00",
    }])
    feed = [{
        "ioc": "example.test",
        "first_seen": "2026-10-15 08:00:00 UTC",
        "last_seen": "2026-10-15 09:00:00 UTC",
    }]

    backfill_threatfox(
        db, dry_run=False, feed_fetcher=fake_feed(feed)
    )

    with sqlite3.connect(db) as con:
        values = con.execute("""
            SELECT source_first_seen, source_last_seen
            FROM ioc_sources WHERE source_name = 'threatfox'
        """).fetchone()
    assert values == (
        "2026-10-15T08:00:00+00:00",
        "2026-10-14T10:00:00+00:00",
    )


def test_unmatched_and_invalid_records_are_skipped(tmp_path):
    db = tmp_path / "test.db"
    make_database(db, [
        {"ioc": "missing.test"},
        {"ioc": "invalid.test"},
    ])
    feed = [{
        "ioc": "invalid.test",
        "first_seen": "not-a-timestamp",
        "last_seen": None,
    }]

    result = backfill_threatfox(
        db, dry_run=True, feed_fetcher=fake_feed(feed)
    )

    assert result["records_to_update"] == 0
    assert result["unmatched"] == 1
    assert result["invalid_first_seen"] == 1


def test_second_run_can_fill_later_last_seen(tmp_path):
    db = tmp_path / "test.db"
    make_database(db, [{"ioc": "example.test"}])

    first_feed = [{
        "ioc": "example.test",
        "first_seen": "2026-10-15 08:00:00 UTC",
        "last_seen": None,
    }]
    backfill_threatfox(
        db, dry_run=False, feed_fetcher=fake_feed(first_feed)
    )

    later_feed = [{
        "ioc": "example.test",
        "first_seen": "2026-10-15 08:00:00 UTC",
        "last_seen": "2026-10-15 09:00:00 UTC",
    }]
    result = backfill_threatfox(
        db, dry_run=False, feed_fetcher=fake_feed(later_feed)
    )

    assert result["last_seen_to_fill"] == 1
    with sqlite3.connect(db) as con:
        last_seen = con.execute("""
            SELECT source_last_seen FROM ioc_sources
            WHERE source_name = 'threatfox'
        """).fetchone()[0]
    assert last_seen == "2026-10-15T09:00:00+00:00"
