from pathlib import Path
from dataclasses import dataclass

from threatlens.collectors.feodo import (
    fetch_feed as fetch_feodo_feed,
    parse_feed as parse_feodo_feed,
)
from threatlens.collectors.threatfox import (
    fetch_feed as fetch_threatfox_feed,
    parse_feed as parse_threatfox_feed,
)
from threatlens.database.ioc_repository import IOCRepository
from threatlens.database.schema import initialize_database


@dataclass
class IngestionResult:
    """Summary of a threat intelligence feed ingestion."""

    feed: str
    fetched: int
    parsed: int
    new: int
    existing: int
    skipped: int



def _ingest_records(
    feed_name: str,
    records: list[dict],
    iocs: list,
    repository: IOCRepository | None = None,
) -> IngestionResult:
    """Store parsed IOCs and summarize ingestion results."""

    if repository is None:
        repository = IOCRepository()

    new = 0
    existing = 0
    skipped = 0

    for ioc in iocs:
        try:
            _, is_new = repository.add_with_status(ioc)

            if is_new:
                new += 1
            else:
                existing += 1

        except (ValueError, TypeError, RuntimeError) as exc:
            skipped += 1
            print(f"Failed to ingest IOC {ioc.value}: {exc}")

    return IngestionResult(
        feed=feed_name,
        fetched=len(records),
        parsed=len(iocs),
        new=new,
        existing=existing,
        skipped=skipped,
    )


def ingest_feodo() -> IngestionResult:
    """Fetch, parse, and store Feodo Tracker IOCs."""

    initialize_database()

    records = fetch_feodo_feed()
    iocs = parse_feodo_feed(records)

    return _ingest_records("feodo-tracker", records, iocs)



def ingest_threatfox(
    days: int = 1,
    database_path: Path | None = None,
) -> IngestionResult:
    """Fetch, parse, and store ThreatFox IOCs."""

    if database_path is None:
        initialize_database()
        repository = IOCRepository()
    else:
        initialize_database(database_path)
        repository = IOCRepository(database_path)

    records = fetch_threatfox_feed(days=days)
    iocs = parse_threatfox_feed(records)

    return _ingest_records(
        "threatfox",
        records,
        iocs,
        repository=repository,
    )
