
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
