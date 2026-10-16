
import pytest

from threatlens.detection.risk_scorer import assess_risk


def test_risk_score_includes_explainable_factors():
    result = assess_risk(
        confidence=85,
        source_count=2,
        threat_type="botnet",
        tags=["c2"],
    )

    assert result.score == 79
    assert result.level == "high"
    assert sum(f.points for f in result.factors) == result.score
    assert len(result.reasons) == 4


def test_zero_evidence_has_low_score():
    result = assess_risk(confidence=0)

    assert result.score == 0
    assert result.level == "low"
    assert result.factors == ()


def test_score_is_capped_at_100():
    result = assess_risk(
        confidence=100,
        source_count=10,
        threat_type="malware",
        tags=["c2", "botnet"],
    )

    assert result.score == 100


@pytest.mark.parametrize("confidence", [-1, 101])
def test_invalid_confidence_is_rejected(confidence):
    with pytest.raises(ValueError, match="confidence"):
        assess_risk(confidence=confidence)


@pytest.mark.parametrize("source_count", [0, -1])
def test_invalid_source_count_is_rejected(source_count):
    with pytest.raises(ValueError, match="source_count"):
        assess_risk(confidence=50, source_count=source_count)


def test_duplicate_and_blank_tags_do_not_inflate_score():
    result = assess_risk(
        confidence=50,
        tags=["c2", "c2", " ", " C2 "],
    )

    tag_factors = [f for f in result.factors if f.name == "tags"]

    assert len(tag_factors) == 1
    assert tag_factors[0].points == 10


def test_threat_type_and_source_tag_are_not_double_counted():
    result = assess_risk(
        confidence=90,
        threat_type="elf.mirai",
        tags=["elf.mirai", "threatfox"],
    )

    assert result.score == 56
    assert result.level == "medium"
    assert any(f.name == "threat_context" for f in result.factors)
    assert not any(f.name == "tags" for f in result.factors)


@pytest.mark.parametrize(
    "source_tag",
    ["threatfox", "feodo-tracker", "THREATFOX"],
)
def test_source_identification_tags_do_not_add_risk_points(source_tag):
    result = assess_risk(
        confidence=50,
        tags=[source_tag],
    )

    assert result.score == 20
    assert not any(f.name == "tags" for f in result.factors)


def test_meaningful_tag_still_contributes_risk_points():
    result = assess_risk(
        confidence=50,
        tags=["c2"],
    )

    assert result.score == 30
    assert any(f.name == "tags" for f in result.factors)


def test_threat_type_tag_matching_is_case_insensitive():
    result = assess_risk(
        confidence=50,
        threat_type="ELF.Mirai",
        tags=["elf.mirai"],
    )

    assert result.score == 40
    assert not any(f.name == "tags" for f in result.factors)


def test_non_string_tags_are_ignored():
    result = assess_risk(
        confidence=50,
        tags=["c2", None, 123],
    )

    assert result.score == 30
    assert any(f.name == "tags" for f in result.factors)
