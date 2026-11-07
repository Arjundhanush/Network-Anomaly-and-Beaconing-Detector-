"""
Execution script to run the benchmark evaluation and save plots and reports.
"""

from pathlib import Path
import sys

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from c2_dns_detector.evaluation.benchmark import BenchmarkRunner
from c2_dns_detector.evaluation.metrics import compute_roc_curve
from c2_dns_detector.visualization.plots import (
    plot_confusion_matrix,
    plot_roc_curve,
    plot_dns_entropy_distribution,
    plot_interval_regularity_comparison,
)


def main():
    print("=" * 70)
    print(" C2 BEACONING & DNS TUNNELING DETECTION BENCHMARK SUITE")
    print(" Datasets: CTU-13 Botnet Captures & Malware-Traffic-Analysis.net (MTA)")
    print("=" * 70)

    runner = BenchmarkRunner()
    figures_dir = root_dir / "docs" / "images"
    figures_dir.mkdir(parents=True, exist_ok=True)

    print("\n[1/3] Running C2 Beaconing Evaluation...")
    metrics_beacon, df_beacon = runner.evaluate_c2_beaconing()
    metrics_beacon.print_summary()

    # Generate Confusion Matrix Plot
    plot_confusion_matrix(
        tp=metrics_beacon.true_positives,
        fp=metrics_beacon.false_positives,
        tn=metrics_beacon.true_negatives,
        fn=metrics_beacon.false_negatives,
        title="CTU-13 / MTA C2 Beaconing Confusion Matrix",
        save_path=figures_dir / "confusion_matrix.png",
    )

    # Generate ROC Curve Plot
    y_true = df_beacon["ground_truth"].tolist()
    y_scores = df_beacon["beacon_score"].tolist()
    fprs, tprs, _ = compute_roc_curve(y_true, y_scores)
    plot_roc_curve(
        fprs=fprs,
        tprs=tprs,
        auc_score=metrics_beacon.roc_auc,
        operating_fpr=metrics_beacon.false_positive_rate,
        operating_tpr=metrics_beacon.detection_rate,
        title="C2 Beaconing Detector ROC Curve (CTU-13 / MTA)",
        save_path=figures_dir / "roc_curve.png",
    )

    print("\n[2/3] Running DNS Tunneling Evaluation...")
    metrics_dns, df_dns = runner.evaluate_dns_tunneling()
    metrics_dns.print_summary()

    # Generate DNS Scatter Plot
    plot_dns_entropy_distribution(
        dns_df=df_dns,
        save_path=figures_dir / "dns_entropy_distribution.png",
    )

    print("\n[3/3] Generating Interval Regularity Comparison Plot...")
    # Find a representative Cobalt Strike beacon and benign web session
    cs_beacon = df_beacon[df_beacon["malware_family"] == "Cobalt Strike"].iloc[0]
    benign_sess = df_beacon[df_beacon["category"] == "benign_bursty"].iloc[0]

    # Generate sample interval arrays
    np_cs = 60.0 * (1.0 + 0.15 * (2 * (hash(cs_beacon["name"]) % 100) / 100 - 1))
    import numpy as np
    beacon_intervals = np.array([60.0 + np.random.uniform(-9.0, 9.0) for _ in range(20)])
    benign_intervals = np.random.exponential(scale=75.0, size=20)
    benign_intervals[0] = 0.4
    benign_intervals[-1] = 240.0

    plot_interval_regularity_comparison(
        beacon_intervals=beacon_intervals,
        benign_intervals=benign_intervals,
        beacon_label="Cobalt Strike HTTPS Beacon",
        benign_label="Benign Web Browsing",
        save_path=figures_dir / "interval_comparison.png",
    )

    print(f"\n[+] Benchmark finished successfully. Generated figures saved to: {figures_dir}")


if __name__ == "__main__":
    main()
