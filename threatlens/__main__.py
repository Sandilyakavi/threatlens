
import argparse
import json
import sys

from threatlens.database.ioc_repository import IOCRepository
from threatlens.database.schema import initialize_database
from threatlens.detection.risk_service import RiskService
from threatlens.detection.freshness import assess_ioc_freshness
from threatlens.models.ioc import IOCType
from threatlens.maintenance import backfill_threatfox


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="ThreatLens — IOC threat intelligence and risk assessment",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    for command in ("assess", "report", "history", "freshness"):
        help_text = {
            "assess": "Assess IOC risk",
            "report": "Generate an IOC investigation report",
            "history": "Show the recorded evidence timeline for an IOC",
            "freshness": "Assess source intelligence observation freshness",
        }[command]

        command_parser = subparsers.add_parser(
            command,
            help=help_text,
        )

        command_parser.add_argument(
            "value",
            help="IOC value to investigate",
        )

        command_parser.add_argument(
            "--type",
            dest="ioc_type",
            choices=[item.value for item in IOCType],
            help="IOC type, required when a value matches multiple types",
        )

        if command == "report":
            command_parser.add_argument(
                "--format",
                choices=("text", "json"),
                default="text",
                help="Report output format (default: text)",
            )

        if command == "history":
            command_parser.add_argument(
                "--format",
                choices=("text", "json"),
                default="text",
                help="History output format (default: text)",
            )

        if command == "freshness":
            command_parser.add_argument(
                "--format",
                choices=("text", "json"),
                default="text",
                help="Freshness output format (default: text)",
            )

    maintenance_parser = subparsers.add_parser(
        "maintenance",
        help="Run database maintenance tasks",
    )
    maintenance_commands = maintenance_parser.add_subparsers(
        dest="maintenance_command",
        required=True,
    )
    backfill_parser = maintenance_commands.add_parser(
        "backfill-threatfox",
        help="Repair missing ThreatFox source timestamps",
    )
    backfill_parser.add_argument(
        "--days",
        type=int,
        choices=range(1, 8),
        default=7,
        help="ThreatFox lookback window in days (default: 7)",
    )
    mode = backfill_parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview proposed repairs without writing (default)",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Create a backup and apply validated repairs",
    )

    return parser


def resolve_ioc_type(
    repository: IOCRepository,
    value: str,
    requested_type: str | None,
) -> str | None:
    if requested_type is not None:
        return requested_type

    matching_types = repository.find_types_by_value(value)

    if not matching_types:
        print(f"IOC not found: {value}", file=sys.stderr)
        return None

    if len(matching_types) > 1:
        available_types = ", ".join(matching_types)

        print(
            "Multiple IOC types match this value; specify --type. "
            f"Available types: {available_types}",
            file=sys.stderr,
        )
        return None

    return matching_types[0]


def parse_source_metadata(source: dict) -> dict:
    """Safely parse metadata recorded for one intelligence source."""
    metadata = source.get("source_metadata")

    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (json.JSONDecodeError, TypeError):
            return {}

    return metadata if isinstance(metadata, dict) else {}


def collect_report_context(record: dict) -> tuple[list[str], list[str]]:
    """Collect unique threat types and raw tags from recorded evidence."""
    threat_types: set[str] = set()
    tags: set[str] = set()

    stored_threat_type = record.get("threat_type")
    if isinstance(stored_threat_type, str) and stored_threat_type.strip():
        threat_types.add(stored_threat_type.strip())

    for source in record.get("sources", []):
        metadata = parse_source_metadata(source)

        threat_type = metadata.get("threat_type")
        if isinstance(threat_type, str) and threat_type.strip():
            threat_types.add(threat_type.strip())

        source_tags = metadata.get("tags", [])
        if isinstance(source_tags, list):
            tags.update(
                tag.strip()
                for tag in source_tags
                if isinstance(tag, str) and tag.strip()
            )

    return sorted(threat_types), sorted(tags)


def build_report_data(
    record: dict,
    assessment,
) -> dict:
    """Build a JSON-serializable IOC investigation report."""
    sources = record.get("sources", [])
    threat_types, tags = collect_report_context(record)

    source_evidence = []

    for source in sources:
        metadata = parse_source_metadata(source)
        source_tags = metadata.get("tags", [])

        if isinstance(source_tags, list):
            clean_tags = sorted(
                {
                    tag.strip()
                    for tag in source_tags
                    if isinstance(tag, str) and tag.strip()
                }
            )
        else:
            clean_tags = []

        threat_type = metadata.get("threat_type")
        if not isinstance(threat_type, str) or not threat_type.strip():
            threat_type = None
        else:
            threat_type = threat_type.strip()

        first_seen = source.get("source_first_seen")
        last_seen = source.get("source_last_seen")

        if first_seen and last_seen:
            timestamp_quality = "complete"
            timestamp_explanation = (
                "Both feed-reported observation timestamps are available."
            )
        elif first_seen or last_seen:
            timestamp_quality = "partial"
            timestamp_explanation = (
                "Only one feed-reported observation timestamp is available."
            )
        else:
            timestamp_quality = "unavailable"
            timestamp_explanation = (
                "No feed-reported observation timestamps are available."
            )

        source_evidence.append(
            {
                "source_name": source.get("source_name", "Unknown"),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "collected_at": source.get("collected_at"),
                "timestamp_quality": timestamp_quality,
                "timestamp_quality_explanation": timestamp_explanation,
                "timestamp_fields_available": {
                    "first_seen": bool(first_seen),
                    "last_seen": bool(last_seen),
                },
                "threat_type": threat_type,
                "raw_feed_tags": clean_tags,
                "metadata_available": bool(metadata),
            }
        )

    timestamp_quality_summary = {
        "complete": sum(
            item["timestamp_quality"] == "complete"
            for item in source_evidence
        ),
        "partial": sum(
            item["timestamp_quality"] == "partial"
            for item in source_evidence
        ),
        "unavailable": sum(
            item["timestamp_quality"] == "unavailable"
            for item in source_evidence
        ),
    }

    factors = [
        {
            "name": factor.name,
            "points": factor.points,
            "explanation": factor.explanation,
        }
        for factor in assessment.factors
    ]

    return {
        "report_type": "ioc_investigation",
        "schema_version": 1,
        "indicator": {
            "value": record["value"],
            "type": record["ioc_type"],
            "stored_threat_level": record.get("threat_level"),
            "first_seen": record.get("first_seen"),
            "last_seen": record.get("last_seen"),
            "created_at": record.get("created_at"),
            "confidence": record.get("confidence", 0),
        },
        "risk_assessment": {
            "score": assessment.score,
            "maximum_score": 100,
            "level": assessment.level,
            "factors": factors,
            "limitations": [
                "The risk score is a heuristic, not proof of malicious activity.",
                "Source independence has not been independently verified.",
                "Feed metadata is reported evidence, not independently validated attribution.",
            ],
        },
        "threat_context": {
            "reported_threat_types": threat_types,
            "raw_feed_tags": tags,
            "conflicting_threat_types": len(threat_types) > 1,
        },
        "source_evidence": {
            "distinct_source_count": record.get(
                "source_count",
                len(sources),
            ),
            "timestamp_quality_summary": timestamp_quality_summary,
            "collection_timestamps_available": all(
                bool(item.get("collected_at"))
                for item in source_evidence
            ) if source_evidence else False,
            "sources": source_evidence,
        },
    }


def print_history(
    value: str,
    ioc_type: str,
    output_format: str = "text",
) -> int:
    """Print the recorded evidence history for an IOC."""
    repository = IOCRepository()
    history = repository.get_evidence_history(value, ioc_type)

    if not history:
        print(
            f"No evidence history found for IOC: {value} (type: {ioc_type})",
            file=sys.stderr,
        )
        return 1

    if output_format == "json":
        print(json.dumps({
            "history_type": "ioc_evidence_history",
            "schema_version": 1,
            "indicator": {"value": value, "type": ioc_type},
            "event_count": len(history),
            "events": history,
        }, indent=2, ensure_ascii=False))
        return 0

    print("=" * 64)
    print("THREATLENS — IOC EVIDENCE TIMELINE")
    print("=" * 64)
    print(f"IOC:   {value}")
    print(f"Type:  {ioc_type}")
    print(f"Events: {len(history)}")

    for index, event in enumerate(history, start=1):
        print(f"\n[{index}] {event['event_type'].replace('_', ' ').upper()}")
        print(f"  Source:   {event.get('source_name') or 'Unknown'}")
        print(f"  Recorded: {event.get('recorded_at') or 'Unknown'}")

        previous = event.get("previous_evidence")
        current = event.get("current_evidence")

        if previous is not None:
            print("  Previous evidence:")
            print("    " + json.dumps(
                previous, sort_keys=True, ensure_ascii=False
            ))
        print("  Current evidence:")
        print("    " + json.dumps(
            current, sort_keys=True, ensure_ascii=False
        ))

    print("=" * 64)
    print("Note: This timeline contains recorded feed evidence changes.")
    print("It does not independently verify that a source's claims are true.")
    return 0


def print_freshness(
    value: str,
    ioc_type: str,
    output_format: str = "text",
) -> int:
    """Print source-specific IOC observation freshness."""
    repository = IOCRepository()
    record = repository.get_correlation(value, ioc_type)

    if record is None:
        print(
            f"IOC not found: {value} (type: {ioc_type})",
            file=sys.stderr,
        )
        return 1

    result = assess_ioc_freshness(record.get("sources", []))
    payload = {
        "assessment_type": "ioc_freshness",
        "schema_version": 1,
        "indicator": {"value": value, "type": ioc_type},
        **result,
    }

    if output_format == "json":
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    print("=" * 64)
    print("THREATLENS — IOC INTELLIGENCE FRESHNESS")
    print("=" * 64)
    print(f"IOC:             {value}")
    print(f"Type:            {ioc_type}")
    print(f"Overall status:  {result['overall_status'].upper()}")
    print(f"Sources:         {result['source_count']}")
    print("Status counts:   " + ", ".join(
        f"{status}={count}"
        for status, count in result["status_counts"].items()
    ))

    for source in result["sources"]:
        print(f"\nSource:          {source['source_name']}")
        print(f"Status:          {source['status'].upper()}")
        print(f"Last observed:   {source['last_seen'] or 'Unknown'}")
        print(f"Collected at:    {source['collected_at'] or 'Unknown'}")
        print(f"Observation age: "
              f"{source['age_days']} days"
              if source["age_days"] is not None
              else "Observation age: Unknown")
        print(f"Explanation:     {source['explanation']}")

    print("=" * 64)
    print("Freshness is separate from risk; unknown does not mean safe.")
    return 0


def print_assessment(value: str, ioc_type: str) -> int:
    repository = IOCRepository()
    record = repository.get_correlation(value, ioc_type)

    if record is None:
        print(
            f"IOC not found: {value} (type: {ioc_type})",
            file=sys.stderr,
        )
        return 1

    result = RiskService().assess(value, ioc_type)

    if result is None:
        print(f"Unable to assess IOC: {value}", file=sys.stderr)
        return 1

    print(f"IOC:        {record['value']}")
    print(f"Type:       {record['ioc_type']}")
    print(f"Risk Score: {result.score}/100")
    print(f"Risk Level: {result.level.upper()}")
    print("\nReasons:")

    if result.reasons:
        for reason in result.reasons:
            print(f"  - {reason}")
    else:
        print("  No supporting evidence available.")

    return 0


def print_report(value: str, ioc_type: str, output_format: str = "text") -> int:
    repository = IOCRepository()
    record = repository.get_correlation(value, ioc_type)

    if record is None:
        print(
            f"IOC not found: {value} (type: {ioc_type})",
            file=sys.stderr,
        )
        return 1

    assessment = RiskService().assess(value, ioc_type)

    if assessment is None:
        print(f"Unable to assess IOC: {value}", file=sys.stderr)
        return 1

    if output_format == "json":
        report_data = build_report_data(record, assessment)
        print(json.dumps(report_data, indent=2, ensure_ascii=False))
        return 0

    sources = record.get("sources", [])
    threat_types, tags = collect_report_context(record)

    print("=" * 64)
    print("THREATLENS — IOC INVESTIGATION REPORT")
    print("=" * 64)

    print("\n[1] Indicator")
    print(f"Value:                {record['value']}")
    print(f"Type:                 {record['ioc_type']}")
    print(
        f"Threat level stored:  "
        f"{record.get('threat_level') or 'Unknown'}"
    )
    print(f"First seen:           {record.get('first_seen') or 'Unknown'}")
    print(f"Last seen:            {record.get('last_seen') or 'Unknown'}")
    print(f"Created at:           {record.get('created_at') or 'Unknown'}")

    print("\n[2] Risk Assessment")
    print(f"Risk score:            {assessment.score}/100")
    print(f"Risk level:            {assessment.level.upper()}")
    print(f"Confidence:            {record.get('confidence', 0)}/100")
    print("Contributing factors:")

    if assessment.reasons:
        for reason in assessment.reasons:
            print(f"  - {reason}")
    else:
        print("  No supporting evidence available.")

    print("\n[3] Threat Context")
    print("Reported threat types:")

    if threat_types:
        for threat_type in threat_types:
            print(f"  - {threat_type}")
    else:
        print("  None recorded")

    print("Raw feed tags (reported by sources):")

    if tags:
        for tag in tags:
            print(f"  - {tag}")
    else:
        print("  None recorded")

    if len(threat_types) > 1:
        print(
            "Warning: Sources report multiple threat types. "
            "Review the evidence before drawing conclusions."
        )

    print("\n[4] Source Evidence")
    print(
        f"Distinct sources: "
        f"{record.get('source_count', len(sources))}"
    )

    if not sources:
        print("  No source-level records available.")
    else:
        for index, source in enumerate(sources, start=1):
            metadata = parse_source_metadata(source)

            print(
                f"\n  Source {index}: "
                f"{source.get('source_name', 'Unknown')}"
            )
            print(
                f"    First seen:  "
                f"{source.get('source_first_seen') or 'Unknown'}"
            )
            print(
                f"    Last seen:   "
                f"{source.get('source_last_seen') or 'Unknown'}"
            )
            print(
                f"    Collected:   "
                f"{source.get('collected_at') or 'Unknown'}"
            )

            threat_type = metadata.get("threat_type")

            if isinstance(threat_type, str) and threat_type.strip():
                print(f"    Threat type: {threat_type.strip()}")
            else:
                print("    Threat type: Unknown")

            source_tags = metadata.get("tags", [])

            if isinstance(source_tags, list):
                clean_tags = sorted(
                    {
                        tag.strip()
                        for tag in source_tags
                        if isinstance(tag, str) and tag.strip()
                    }
                )
            else:
                clean_tags = []

            if clean_tags:
                print(f"    Raw feed tags: {', '.join(clean_tags)}")
            else:
                print("    Raw feed tags: None recorded")

            if not metadata:
                print("    Metadata status: Missing or invalid")

    print("\n[5] Evidence Limitations")
    print(
        "  - The risk score is a heuristic, not proof of malicious activity."
    )
    print(
        "  - Source independence has not been independently verified."
    )
    print(
        "  - Feed metadata is reported evidence, not independently "
        "validated attribution."
    )
    print(
        "  - Missing timestamps or metadata are shown as unknown."
    )
    print("=" * 64)

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "maintenance":
        try:
            result = backfill_threatfox(
                days=args.days,
                dry_run=not args.apply,
            )
        except Exception as exc:
            print(f"Maintenance failed: {exc}", file=sys.stderr)
            return 1

        print(json.dumps(result, indent=2))
        return 0

    # Create any missing tables/indexes before database operations.
    initialize_database()
    repository = IOCRepository()

    ioc_type = resolve_ioc_type(
        repository,
        args.value,
        args.ioc_type,
    )

    if ioc_type is None:
        matching_types = repository.find_types_by_value(args.value)
        return 2 if len(matching_types) > 1 else 1

    if args.command == "assess":
        return print_assessment(args.value, ioc_type)

    if args.command == "report":
        return print_report(args.value, ioc_type, args.format)

    if args.command == "history":
        return print_history(args.value, ioc_type, args.format)

    if args.command == "freshness":
        return print_freshness(args.value, ioc_type, args.format)

    parser.error("Unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
