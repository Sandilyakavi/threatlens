
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
