"""Metrics for comparing IOC predictions with reviewed ground-truth labels."""

from collections.abc import Iterable

VALID_LABELS = {"malicious", "benign", "unknown"}
BINARY_LABELS = {"malicious", "benign"}


def calculate_metrics(
    comparisons: Iterable[dict],
) -> dict:
    """Calculate binary classification metrics, excluding unknown truth labels.

    Each comparison must contain:
      - label: malicious, benign, or unknown
      - prediction: malicious or benign, or None if unavailable

    Predictions must come from the system under evaluation, not be copied
    from the ground-truth labels.
    """
    counts = {
        "tp": 0,
        "fp": 0,
        "tn": 0,
        "fn": 0,
    }
    unknown_count = 0
    unavailable_prediction_count = 0

    for index, item in enumerate(comparisons, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"comparison {index} must be a dictionary")

        label = item.get("label")
        prediction = item.get("prediction")

        if label not in VALID_LABELS:
            raise ValueError(
                f"comparison {index}: invalid label {label!r}"
            )

        if label == "unknown":
            unknown_count += 1
            continue

        if prediction is None:
            unavailable_prediction_count += 1
            continue

        if prediction not in BINARY_LABELS:
            raise ValueError(
                f"comparison {index}: invalid prediction {prediction!r}"
            )

        if label == "malicious" and prediction == "malicious":
            counts["tp"] += 1
        elif label == "benign" and prediction == "malicious":
            counts["fp"] += 1
        elif label == "benign" and prediction == "benign":
            counts["tn"] += 1
        else:
            counts["fn"] += 1

    tp, fp = counts["tp"], counts["fp"]
    tn, fn = counts["tn"], counts["fn"]

    def ratio(numerator: int, denominator: int) -> float | None:
        if denominator == 0:
            return None
        return numerator / denominator

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    false_positive_rate = ratio(fp, fp + tn)

    evaluated = tp + fp + tn + fn

    return {
        "confusion_matrix": {
            "true_positive": tp,
            "false_positive": fp,
            "true_negative": tn,
            "false_negative": fn,
        },
        "counts": {
            "evaluated": evaluated,
            "unknown_ground_truth": unknown_count,
            "unavailable_predictions": unavailable_prediction_count,
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "false_positive_rate": false_positive_rate,
        },
        "metric_status": {
            "precision": (
                "available" if tp + fp else "not_available_no_positive_predictions"
            ),
            "recall": (
                "available" if tp + fn else "not_available_no_positive_labels"
            ),
            "false_positive_rate": (
                "available" if fp + tn else "not_available_no_benign_labels"
            ),
        },
    }


def predict_from_score(
    score: int | None,
    *,
    threshold: int = 60,
) -> str | None:
    """Map a risk score to a binary prediction using an explicit threshold.

    This is an evaluation policy, not a claim that low-scoring indicators
    are actually benign.
    """
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise ValueError("threshold must be an integer from 0 to 100")
    if not 0 <= threshold <= 100:
        raise ValueError("threshold must be from 0 to 100")

    if score is None:
        return None
    if not isinstance(score, int) or isinstance(score, bool):
        raise ValueError("score must be an integer from 0 to 100 or None")
    if not 0 <= score <= 100:
        raise ValueError("score must be from 0 to 100")

    return "malicious" if score >= threshold else "benign"
