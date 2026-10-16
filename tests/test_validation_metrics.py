import pytest

from threatlens.validation.metrics import calculate_metrics


def test_calculates_binary_metrics_and_confusion_matrix():
    result = calculate_metrics([
        {"label": "malicious", "prediction": "malicious"},
        {"label": "malicious", "prediction": "benign"},
        {"label": "benign", "prediction": "malicious"},
        {"label": "benign", "prediction": "benign"},
        {"label": "unknown", "prediction": "malicious"},
    ])

    assert result["confusion_matrix"] == {
        "true_positive": 1,
        "false_positive": 1,
        "true_negative": 1,
        "false_negative": 1,
    }
    assert result["counts"]["evaluated"] == 4
    assert result["counts"]["unknown_ground_truth"] == 1
    assert result["metrics"]["precision"] == pytest.approx(0.5)
    assert result["metrics"]["recall"] == pytest.approx(0.5)
    assert result["metrics"]["false_positive_rate"] == pytest.approx(0.5)


def test_zero_denominators_are_not_reported_as_zero_percent():
    result = calculate_metrics([
        {"label": "benign", "prediction": "benign"},
    ])

    assert result["metrics"]["precision"] is None
    assert result["metrics"]["recall"] is None
    assert result["metrics"]["false_positive_rate"] == 0.0
    assert result["metric_status"]["precision"].startswith("not_available")
    assert result["metric_status"]["recall"].startswith("not_available")


def test_unknown_labels_are_excluded():
    result = calculate_metrics([
        {"label": "unknown", "prediction": "malicious"},
        {"label": "unknown", "prediction": None},
    ])

    assert result["counts"]["evaluated"] == 0
    assert result["counts"]["unknown_ground_truth"] == 2
    assert result["metrics"]["precision"] is None
    assert result["metrics"]["recall"] is None
    assert result["metrics"]["false_positive_rate"] is None


def test_missing_prediction_is_counted_not_guessed():
    result = calculate_metrics([
        {"label": "malicious", "prediction": None},
        {"label": "benign", "prediction": "benign"},
    ])

    assert result["counts"]["evaluated"] == 1
    assert result["counts"]["unavailable_predictions"] == 1
    assert result["confusion_matrix"]["true_negative"] == 1


@pytest.mark.parametrize("label", ["", "unknown-label", None])
def test_rejects_invalid_ground_truth_labels(label):
    with pytest.raises(ValueError, match="invalid label"):
        calculate_metrics([
            {"label": label, "prediction": "benign"},
        ])


def test_rejects_invalid_predictions():
    with pytest.raises(ValueError, match="invalid prediction"):
        calculate_metrics([
            {"label": "malicious", "prediction": "maybe"},
        ])


def test_prediction_threshold_is_explicit():
    from threatlens.validation.metrics import predict_from_score

    assert predict_from_score(60, threshold=60) == "malicious"
    assert predict_from_score(59, threshold=60) == "benign"
    assert predict_from_score(None, threshold=60) is None


@pytest.mark.parametrize("score", [-1, 101])
def test_prediction_rejects_invalid_score(score):
    from threatlens.validation.metrics import predict_from_score

    with pytest.raises(ValueError, match="score"):
        predict_from_score(score, threshold=60)


def test_prediction_rejects_invalid_threshold():
    from threatlens.validation.metrics import predict_from_score

    with pytest.raises(ValueError, match="threshold"):
        predict_from_score(50, threshold=101)
