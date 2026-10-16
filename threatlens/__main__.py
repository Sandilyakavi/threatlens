
import argparse
import sys

from threatlens.database.ioc_repository import IOCRepository
from threatlens.detection.risk_service import RiskService
from threatlens.models.ioc import IOCType


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="ThreatLens — IOC threat intelligence and risk assessment",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    assess_parser = subparsers.add_parser(
        "assess",
        help="Assess the risk of an IOC stored in the database",
    )

    assess_parser.add_argument(
        "value",
        help="IOC value to assess",
    )

    assess_parser.add_argument(
        "--type",
        dest="ioc_type",
        choices=[item.value for item in IOCType],
        help="IOC type, required when a value matches multiple types",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command != "assess":
        parser.error("Unsupported command")

    repository = IOCRepository()

    # Resolve the IOC type before requesting a risk assessment.
    if args.ioc_type is None:
        matching_types = repository.find_types_by_value(args.value)

        if not matching_types:
            print(f"IOC not found: {args.value}", file=sys.stderr)
            return 1

        if len(matching_types) > 1:
            print(
                "Multiple IOC types match this value; specify --type. "
                f"Available types: {', '.join(matching_types)}",
                file=sys.stderr,
            )
            return 2

        ioc_type = matching_types[0]
    else:
        ioc_type = args.ioc_type

    record = repository.get_correlation(args.value, ioc_type)

    if record is None:
        print(
            f"IOC not found: {args.value} (type: {ioc_type})",
            file=sys.stderr,
        )
        return 1

    result = RiskService().assess(args.value, ioc_type)

    if result is None:
        print(f"Unable to assess IOC: {args.value}", file=sys.stderr)
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


if __name__ == "__main__":
    raise SystemExit(main())
