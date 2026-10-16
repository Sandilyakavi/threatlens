"""Load and validate independently reviewed IOC labels from JSONL."""

import json
from pathlib import Path
from urllib.parse import urlparse


ALLOWED_LABELS = {"malicious", "benign", "unknown"}
REQUIRED_FIELDS = {
    "indicator",
    "ioc_type",
    "label",
    "evidence_source",
    "evidence_url",
    "reviewed_at",
    "notes",
}


def validate_record(record: object, line_number: int) -> list[str]:
    """Return validation errors for one labelled IOC record."""
    errors = []

    if not isinstance(record, dict):
        return [f"line {line_number}: record must be a JSON object"]

    missing = REQUIRED_FIELDS - record.keys()
    if missing:
        errors.append(
            f"line {line_number}: missing fields: {', '.join(sorted(missing))}"
        )

    indicator = record.get("indicator")
    if not isinstance(indicator, str) or not indicator.strip():
        errors.append(f"line {line_number}: indicator must be a non-empty string")

    ioc_type = record.get("ioc_type")
    if not isinstance(ioc_type, str) or not ioc_type.strip():
        errors.append(f"line {line_number}: ioc_type must be a non-empty string")

    label = record.get("label")
    if label not in ALLOWED_LABELS:
        errors.append(
            f"line {line_number}: label must be one of "
            f"{', '.join(sorted(ALLOWED_LABELS))}"
        )

    evidence_source = record.get("evidence_source")
    evidence_url = record.get("evidence_url")
    reviewed_at = record.get("reviewed_at")

    if label in {"malicious", "benign"}:
        if not isinstance(evidence_source, str) or not evidence_source.strip():
            errors.append(
                f"line {line_number}: labelled records require evidence_source"
            )

        if not isinstance(evidence_url, str) or not evidence_url.strip():
            errors.append(
                f"line {line_number}: labelled records require evidence_url"
            )
        else:
            parsed_url = urlparse(evidence_url)
            if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
                errors.append(
                    f"line {line_number}: evidence_url must be an HTTP(S) URL"
                )

        if not isinstance(reviewed_at, str) or not reviewed_at.strip():
            errors.append(
                f"line {line_number}: labelled records require reviewed_at"
            )

    score = record.get("score")
    if score is not None:
        if not isinstance(score, int) or isinstance(score, bool):
            errors.append(f"line {line_number}: score must be an integer from 0 to 100 or null")
        elif not 0 <= score <= 100:
            errors.append(f"line {line_number}: score must be from 0 to 100")

    notes = record.get("notes")
    if notes is not None and not isinstance(notes, str):
        errors.append(f"line {line_number}: notes must be a string or null")

    return errors


def load_dataset(path: Path) -> tuple[list[dict], list[str]]:
    """Load JSONL records and report malformed or invalid rows."""
    records = []
    errors = []
    path = Path(path)

    try:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, raw_line in enumerate(stream, start=1):
                if not raw_line.strip():
                    continue

                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    errors.append(
                        f"line {line_number}: invalid JSON ({exc.msg})"
                    )
                    continue

                record_errors = validate_record(record, line_number)
                errors.extend(record_errors)

                if isinstance(record, dict) and not record_errors:
                    records.append(record)

    except OSError as exc:
        return [], [f"cannot read dataset: {exc}"]

    seen = set()
    for index, record in enumerate(records, start=1):
        key = (record["indicator"].strip(), record["ioc_type"].strip())
        if key in seen:
            errors.append(
                f"valid record {index}: duplicate indicator and IOC type"
            )
        seen.add(key)

    return records, errors
