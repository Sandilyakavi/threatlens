from dataclasses import dataclass

from threatlens.collectors.feodo import fetch_feed, parse_feed
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


def ingest_feodo() -> IngestionResult:
    """Fetch, parse, and store Feodo Tracker IOCs."""

    initialize_database()

    records = fetch_feed()
    iocs = parse_feed(records)

    repository = IOCRepository()

    new = 0
    existing = 0
    skipped = 0

    for ioc in iocs:
        try:
            existing_ioc = repository.find_by_value(ioc.value)

            repository.add(ioc)

            if existing_ioc is None:
                new += 1
            else:
                existing += 1

        except Exception:
            skipped += 1

    return IngestionResult(
        feed="feodo-tracker",
        fetched=len(records),
        parsed=len(iocs),
        new=new,
        existing=existing,
        skipped=skipped,
    )
