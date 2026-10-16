
import sys

from threatlens import __main__ as cli
from threatlens.detection.risk_scorer import RiskAssessment, RiskFactor


class FakeRepository:
    def __init__(self):
        self.record = {
            "value": "example.test",
            "ioc_type": "domain",
        }

    def find_types_by_value(self, value):
        if value == "missing.test":
            return []
        if value == "ambiguous.test":
            return ["domain", "url"]
        return ["domain"]

    def get_correlation(self, value, ioc_type=None):
        if value == "missing.test":
            return None
        if value == "ambiguous.test" and ioc_type is None:
            return None
        return {
            "value": value,
            "ioc_type": ioc_type or "domain",
        }


class FakeRiskService:
    def assess(self, value, ioc_type):
        return RiskAssessment(
            score=66,
            level="high",
            factors=(
                RiskFactor(
                    name="confidence",
                    points=36,
                    explanation="Feed confidence is 90/100 (+36).",
                ),
                RiskFactor(
                    name="threat_context",
                    points=20,
                    explanation="Threat type is identified as elf.mirai (+20).",
                ),
                RiskFactor(
                    name="tags",
                    points=10,
                    explanation="Feed provides contextual tags: threatfox (+10).",
                ),
            ),
        )


def setup_cli(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["threatlens", *argv])
    monkeypatch.setattr(cli, "IOCRepository", FakeRepository)
    monkeypatch.setattr(cli, "initialize_database", lambda: None)
    monkeypatch.setattr(cli, "RiskService", FakeRiskService)


def test_assess_displays_risk_report(monkeypatch, capsys):
    setup_cli(monkeypatch, ["assess", "example.test", "--type", "domain"])

    assert cli.main() == 0

    output = capsys.readouterr().out
    assert "IOC:        example.test" in output
    assert "Type:       domain" in output
    assert "Risk Score: 66/100" in output
    assert "Risk Level: HIGH" in output
    assert "Feed confidence is 90/100" in output


def test_assess_detects_type_automatically(monkeypatch, capsys):
    setup_cli(monkeypatch, ["assess", "example.test"])

    assert cli.main() == 0

    output = capsys.readouterr().out
    assert "Type:       domain" in output


def test_assess_returns_error_for_unknown_ioc(monkeypatch, capsys):
    setup_cli(monkeypatch, ["assess", "missing.test", "--type", "domain"])

    assert cli.main() == 1

    error = capsys.readouterr().err
    assert "IOC not found: missing.test" in error


def test_assess_requires_type_for_ambiguous_ioc(monkeypatch, capsys):
    setup_cli(monkeypatch, ["assess", "ambiguous.test"])

    assert cli.main() == 2

    error = capsys.readouterr().err
    assert "Multiple IOC types match this value" in error
    assert "domain, url" in error

def test_report_displays_indicator_risk_and_source_evidence(
    monkeypatch, capsys
):
    setup_cli(monkeypatch, ["report", "example.test", "--type", "domain"])

    class ReportRepository(FakeRepository):
        def get_correlation(self, value, ioc_type=None):
            return {
                "value": value,
                "ioc_type": ioc_type,
                "threat_level": "low",
                "confidence": 90,
                "first_seen": None,
                "last_seen": None,
                "created_at": "2026-10-15T08:00:00+00:00",
                "source_count": 1,
                "sources": [
                    {
                        "source_name": "threatfox",
                        "source_first_seen": None,
                        "source_last_seen": None,
                        "collected_at": "2026-10-15T08:01:00+00:00",
                        "source_metadata": (
                            '{"threat_type": "elf.mirai", '
                            '"tags": ["threatfox", "elf.mirai"]}'
                        ),
                    }
                ],
            }

    monkeypatch.setattr(cli, "IOCRepository", ReportRepository)

    assert cli.main() == 0

    output = capsys.readouterr().out
    assert "THREATLENS — IOC INVESTIGATION REPORT" in output
    assert "Risk score:            66/100" in output
    assert "elf.mirai" in output
    assert "Source 1: threatfox" in output
    assert "Source independence has not been independently verified." in output


def test_report_warns_about_conflicting_threat_types(
    monkeypatch, capsys
):
    setup_cli(monkeypatch, ["report", "example.test", "--type", "domain"])

    class ConflictingRepository(FakeRepository):
        def get_correlation(self, value, ioc_type=None):
            return {
                "value": value,
                "ioc_type": ioc_type,
                "threat_level": "medium",
                "confidence": 50,
                "first_seen": None,
                "last_seen": None,
                "created_at": None,
                "source_count": 2,
                "sources": [
                    {
                        "source_name": "feed-one",
                        "source_metadata": '{"threat_type": "botnet", "tags": []}',
                    },
                    {
                        "source_name": "feed-two",
                        "source_metadata": '{"threat_type": "phishing", "tags": []}',
                    },
                ],
            }

    monkeypatch.setattr(cli, "IOCRepository", ConflictingRepository)

    assert cli.main() == 0

    output = capsys.readouterr().out
    assert "botnet" in output
    assert "phishing" in output
    assert "Sources report multiple threat types." in output

def test_report_json_outputs_valid_machine_readable_json(
    monkeypatch, capsys
):
    import json

    setup_cli(
        monkeypatch,
        [
            "report",
            "example.test",
            "--type",
            "domain",
            "--format",
            "json",
        ],
    )

    class JsonReportRepository(FakeRepository):
        def get_correlation(self, value, ioc_type=None):
            return {
                "value": value,
                "ioc_type": ioc_type,
                "threat_level": "low",
                "confidence": 90,
                "first_seen": None,
                "last_seen": None,
                "created_at": "2026-10-15T08:00:00+00:00",
                "source_count": 1,
                "threat_type": None,
                "sources": [
                    {
                        "source_name": "threatfox",
                        "source_first_seen": None,
                        "source_last_seen": None,
                        "collected_at": "2026-10-15T08:01:00+00:00",
                        "source_metadata": (
                            '{"threat_type": "elf.mirai", '
                            '"tags": ["threatfox", "elf.mirai"]}'
                        ),
                    }
                ],
            }

    monkeypatch.setattr(cli, "IOCRepository", JsonReportRepository)

    assert cli.main() == 0

    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert captured.err == ""
    assert report["report_type"] == "ioc_investigation"
    assert report["schema_version"] == 1
    assert report["indicator"]["value"] == "example.test"
    assert report["indicator"]["type"] == "domain"
    assert report["risk_assessment"]["score"] == 66
    assert report["risk_assessment"]["level"] == "high"
    assert report["risk_assessment"]["factors"][0]["name"] == "confidence"
    assert report["threat_context"]["reported_threat_types"] == ["elf.mirai"]
    assert report["threat_context"]["raw_feed_tags"] == [
        "elf.mirai",
        "threatfox",
    ]
    assert report["source_evidence"]["distinct_source_count"] == 1
    assert report["source_evidence"]["sources"][0]["source_name"] == "threatfox"
    assert report["source_evidence"]["sources"][0]["raw_feed_tags"] == [
        "elf.mirai",
        "threatfox",
    ]
    source = report["source_evidence"]["sources"][0]
    assert source["timestamp_quality"] == "unavailable"
    assert source["timestamp_fields_available"] == {
        "first_seen": False,
        "last_seen": False,
    }
    assert source["timestamp_quality_explanation"]
    assert report["source_evidence"]["timestamp_quality_summary"] == {
        "complete": 0,
        "partial": 0,
        "unavailable": 1,
    }
    assert report["source_evidence"]["collection_timestamps_available"] is True


def test_report_defaults_to_text_format(monkeypatch, capsys):
    setup_cli(
        monkeypatch,
        ["report", "example.test", "--type", "domain"],
    )

    class TextReportRepository(FakeRepository):
        def get_correlation(self, value, ioc_type=None):
            return {
                "value": value,
                "ioc_type": ioc_type,
                "threat_level": "low",
                "confidence": 90,
                "first_seen": None,
                "last_seen": None,
                "created_at": None,
                "source_count": 1,
                "sources": [],
            }

    monkeypatch.setattr(cli, "IOCRepository", TextReportRepository)

    assert cli.main() == 0

    output = capsys.readouterr().out
    assert "THREATLENS — IOC INVESTIGATION REPORT" in output
    assert not output.lstrip().startswith("{")

def test_build_report_data_marks_partial_timestamps():
    assessment = RiskAssessment(
        score=20,
        level="low",
        factors=(),
    )
    record = {
        "value": "example.test",
        "ioc_type": "domain",
        "threat_level": "low",
        "confidence": 0,
        "first_seen": "2026-10-10T00:00:00+00:00",
        "last_seen": None,
        "created_at": "2026-10-15T08:00:00+00:00",
        "source_count": 1,
        "sources": [
            {
                "source_name": "test-feed",
                "source_first_seen": "2026-10-10T00:00:00+00:00",
                "source_last_seen": None,
                "collected_at": "2026-10-15T08:01:00+00:00",
                "source_metadata": '{"threat_type": "test-malware", "tags": []}',
            }
        ],
    }

    report = cli.build_report_data(record, assessment)
    source = report["source_evidence"]["sources"][0]

    assert source["timestamp_quality"] == "partial"
    assert source["timestamp_fields_available"] == {
        "first_seen": True,
        "last_seen": False,
    }
    assert report["source_evidence"]["timestamp_quality_summary"] == {
        "complete": 0,
        "partial": 1,
        "unavailable": 0,
    }


def test_build_report_data_marks_complete_timestamps():
    assessment = RiskAssessment(
        score=20,
        level="low",
        factors=(),
    )
    record = {
        "value": "example.test",
        "ioc_type": "domain",
        "threat_level": "low",
        "confidence": 0,
        "created_at": "2026-10-15T08:00:00+00:00",
        "source_count": 1,
        "sources": [
            {
                "source_name": "test-feed",
                "source_first_seen": "2026-10-10T00:00:00+00:00",
                "source_last_seen": "2026-10-12T00:00:00+00:00",
                "collected_at": "2026-10-15T08:01:00+00:00",
                "source_metadata": None,
            }
        ],
    }

    report = cli.build_report_data(record, assessment)
    source = report["source_evidence"]["sources"][0]

    assert source["timestamp_quality"] == "complete"
    assert report["source_evidence"]["timestamp_quality_summary"] == {
        "complete": 1,
        "partial": 0,
        "unavailable": 0,
    }


class HistoryRepository(FakeRepository):
    def get_evidence_history(self, value, ioc_type=None):
        if value == "missing.test":
            return []
        return [
            {
                "id": 1,
                "value": value,
                "ioc_type": ioc_type,
                "source_name": "test-feed",
                "event_type": "source_added",
                "previous_evidence": None,
                "current_evidence": {
                    "first_seen": None,
                    "last_seen": None,
                    "metadata": {"threat_type": "test-malware"},
                },
                "recorded_at": "2026-10-16T00:00:00+00:00",
            },
            {
                "id": 2,
                "value": value,
                "ioc_type": ioc_type,
                "source_name": "test-feed",
                "event_type": "evidence_updated",
                "previous_evidence": {"metadata": {"tags": ["old"]}},
                "current_evidence": {"metadata": {"tags": ["new"]}},
                "recorded_at": "2026-10-16T00:01:00+00:00",
            },
        ]


def test_history_displays_evidence_timeline(monkeypatch, capsys):
    setup_cli(
        monkeypatch,
        ["history", "example.test", "--type", "domain"],
    )
    monkeypatch.setattr(cli, "IOCRepository", HistoryRepository)

    assert cli.main() == 0
    output = capsys.readouterr().out
    assert "THREATLENS — IOC EVIDENCE TIMELINE" in output
    assert "SOURCE ADDED" in output
    assert "EVIDENCE UPDATED" in output
    assert "test-feed" in output
    assert "test-malware" in output
    assert '"old"' in output
    assert '"new"' in output


def test_history_json_is_valid_and_machine_readable(monkeypatch, capsys):
    import json

    setup_cli(
        monkeypatch,
        [
            "history", "example.test",
            "--type", "domain",
            "--format", "json",
        ],
    )
    monkeypatch.setattr(cli, "IOCRepository", HistoryRepository)

    assert cli.main() == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert captured.err == ""
    assert result["history_type"] == "ioc_evidence_history"
    assert result["event_count"] == 2
    assert result["indicator"]["type"] == "domain"
    assert result["events"][1]["event_type"] == "evidence_updated"


def test_history_returns_error_when_no_events_exist(monkeypatch, capsys):
    setup_cli(
        monkeypatch,
        ["history", "missing.test", "--type", "domain"],
    )
    monkeypatch.setattr(cli, "IOCRepository", HistoryRepository)

    assert cli.main() == 1
    assert "No evidence history found" in capsys.readouterr().err


class FreshnessRepository(FakeRepository):
    def get_correlation(self, value, ioc_type=None):
        if value == "missing.test":
            return None

        return {
            "value": value,
            "ioc_type": ioc_type or "domain",
            "sources": [
                {
                    "source_name": "test-feed",
                    "source_last_seen": "2026-10-15T12:00:00+00:00",
                    "collected_at": "2026-10-16T08:00:00+00:00",
                }
            ],
        }


class UnknownFreshnessRepository(FreshnessRepository):
    def get_correlation(self, value, ioc_type=None):
        record = super().get_correlation(value, ioc_type)
        if record is not None:
            record["sources"] = [
                {
                    "source_name": "test-feed",
                    "source_last_seen": None,
                    "collected_at": "2026-10-16T08:00:00+00:00",
                }
            ]
        return record


def test_freshness_displays_source_status(monkeypatch, capsys):
    setup_cli(
        monkeypatch,
        ["freshness", "example.test", "--type", "domain"],
    )
    monkeypatch.setattr(cli, "IOCRepository", FreshnessRepository)

    assert cli.main() == 0

    output = capsys.readouterr().out
    assert "THREATLENS — IOC INTELLIGENCE FRESHNESS" in output
    assert "Overall status:" in output
    assert "Source:          test-feed" in output
    assert "Last observed:" in output
    assert "Freshness is separate from risk" in output


def test_freshness_json_is_valid_and_machine_readable(
    monkeypatch, capsys
):
    import json

    setup_cli(
        monkeypatch,
        [
            "freshness", "example.test",
            "--type", "domain",
            "--format", "json",
        ],
    )
    monkeypatch.setattr(cli, "IOCRepository", FreshnessRepository)

    assert cli.main() == 0

    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert captured.err == ""
    assert result["assessment_type"] == "ioc_freshness"
    assert result["schema_version"] == 1
    assert result["indicator"]["value"] == "example.test"
    assert result["indicator"]["type"] == "domain"
    assert result["source_count"] == 1
    assert result["sources"][0]["source_name"] == "test-feed"


def test_freshness_returns_error_for_unknown_ioc(monkeypatch, capsys):
    setup_cli(
        monkeypatch,
        ["freshness", "missing.test", "--type", "domain"],
    )
    monkeypatch.setattr(cli, "IOCRepository", FreshnessRepository)

    assert cli.main() == 1

    captured = capsys.readouterr()
    assert "IOC not found: missing.test" in captured.err
    assert captured.out == ""


def test_freshness_missing_observation_timestamp_is_unknown(
    monkeypatch, capsys
):
    import json

    setup_cli(
        monkeypatch,
        [
            "freshness", "example.test",
            "--type", "domain",
            "--format", "json",
        ],
    )
    monkeypatch.setattr(
        cli, "IOCRepository", UnknownFreshnessRepository
    )

    assert cli.main() == 0

    result = json.loads(capsys.readouterr().out)
    assert result["overall_status"] == "unknown"
    assert result["status_counts"]["unknown"] == 1
    assert result["sources"][0]["status"] == "unknown"
    assert result["sources"][0]["age_days"] is None
