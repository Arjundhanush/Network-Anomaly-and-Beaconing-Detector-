"""
Evaluation metrics for intrusion detection and classification.
Computes True Positive Rate (Detection Rate), False Positive Rate, Precision, F1-Score,
Confusion Matrix, and ROC Curve with AUC.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class EvaluationMetrics:
    """Evaluation summary metrics container."""
    total_samples: int
    positives: int
    negatives: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    detection_rate: float      # Recall / TPR = TP / (TP + FN)
    false_positive_rate: float # FPR = FP / (FP + TN)
    precision: float           # PPV = TP / (TP + FP)
    specificity: float         # TNR = TN / (TN + FP)
    accuracy: float            # (TP + TN) / Total
    f1_score: float            # 2 * P * R / (P + R)
    roc_auc: float             # Area Under ROC Curve

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def print_summary(self) -> None:
        """Print formatted terminal report."""
        print("=" * 60)
        print("          DETECTION PERFORMANCE EVALUATION REPORT")
        print("=" * 60)
        print(f"Total Evaluated Samples : {self.total_samples:,}")
        print(f"Ground Truth Positives  : {self.positives:,}")
        print(f"Ground Truth Negatives  : {self.negatives:,}")
        print("-" * 60)
        print(f"True Positives (TP)     : {self.true_positives} / {self.positives} ({self.detection_rate * 100:.2f}%)")
        print(f"False Negatives (FN)    : {self.false_negatives} / {self.positives} ({(1 - self.detection_rate) * 100:.2f}%)")
        print(f"False Positives (FP)    : {self.false_positives} / {self.negatives} ({self.false_positive_rate * 100:.2f}%)")
        print(f"True Negatives (TN)     : {self.true_negatives} / {self.negatives} ({self.specificity * 100:.2f}%)")
        print("-" * 60)
        print(f"Detection Rate (Recall) : {self.detection_rate * 100:.2f}%")
        print(f"False Positive Rate     : {self.false_positive_rate * 100:.2f}%")
        print(f"Precision               : {self.precision * 100:.2f}%")
        print(f"Specificity             : {self.specificity * 100:.2f}%")
        print(f"Accuracy                : {self.accuracy * 100:.2f}%")
        print(f"F1-Score                : {self.f1_score:.4f}")
        print(f"ROC AUC                 : {self.roc_auc:.4f}")
        print("=" * 60)


def compute_metrics(
    y_true: List[int],
    y_pred: List[int],
    y_scores: Optional[List[float]] = None
) -> EvaluationMetrics:
    """
    Compute binary classification performance metrics.

    Args:
        y_true: Ground truth binary labels (1 = positive/malicious, 0 = negative/benign).
        y_pred: Predicted binary labels (1 or 0).
        y_scores: Continuous confidence scores (optional, for ROC curve & AUC).

    Returns:
        EvaluationMetrics dataclass instance.
    """
    y_t = np.array(y_true, dtype=int)
    y_p = np.array(y_pred, dtype=int)

    tp = int(np.sum((y_t == 1) & (y_p == 1)))
    fp = int(np.sum((y_t == 0) & (y_p == 1)))
    tn = int(np.sum((y_t == 0) & (y_p == 0)))
    fn = int(np.sum((y_t == 1) & (y_p == 0)))

    pos = int(np.sum(y_t == 1))
    neg = int(np.sum(y_t == 0))
    total = len(y_t)

    tpr = tp / pos if pos > 0 else 0.0
    fpr = fp / neg if neg > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    specificity = tn / neg if neg > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    f1 = (2 * precision * tpr) / (precision + tpr) if (precision + tpr) > 0 else 0.0

    if y_scores is not None and len(y_scores) == total:
        auc = compute_roc_auc(y_true, y_scores)
    else:
        # Approximate AUC using single operating point
        auc = (tpr + specificity) / 2.0

    return EvaluationMetrics(
        total_samples=total,
        positives=pos,
        negatives=neg,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        detection_rate=round(tpr, 4),
        false_positive_rate=round(fpr, 4),
        precision=round(precision, 4),
        specificity=round(specificity, 4),
        accuracy=round(accuracy, 4),
        f1_score=round(f1, 4),
        roc_auc=round(auc, 4),
    )


def compute_roc_curve(
    y_true: List[int],
    y_scores: List[float],
    num_thresholds: int = 101
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Compute False Positive Rate and True Positive Rate coordinates across thresholds.
    
    Returns:
        Tuple of (fpr_array, tpr_array, thresholds_array)
    """
    y_t = np.array(y_true, dtype=int)
    scores = np.array(y_scores, dtype=float)

    pos = np.sum(y_t == 1)
    neg = np.sum(y_t == 0)

    thresholds = np.linspace(0.0, 100.0, num_thresholds)
    fprs = []
    tprs = []

    for th in thresholds:
        preds = (scores >= th).astype(int)
        tp = np.sum((y_t == 1) & (preds == 1))
        fp = np.sum((y_t == 0) & (preds == 1))
        tprs.append(tp / pos if pos > 0 else 0.0)
        fprs.append(fp / neg if neg > 0 else 0.0)

    # Sort coordinates by FPR ascending
    sort_idx = np.argsort(fprs)
    return np.array(fprs)[sort_idx], np.array(tprs)[sort_idx], thresholds[sort_idx]


def compute_roc_auc(y_true: List[int], y_scores: List[float]) -> float:
    """Compute Area Under the ROC Curve using trapezoidal rule."""
    fprs, tprs, _ = compute_roc_curve(y_true, y_scores)
    # Ensure (0,0) and (1,1) endpoints are present
    fpr_extended = np.concatenate(([0.0], fprs, [1.0]))
    tpr_extended = np.concatenate(([0.0], tprs, [1.0]))
    sort_idx = np.argsort(fpr_extended)
    trap_fn = getattr(np, "trapezoid", getattr(np, "trapz", None))
    auc = trap_fn(tpr_extended[sort_idx], fpr_extended[sort_idx])
    return float(np.clip(auc, 0.0, 1.0))
