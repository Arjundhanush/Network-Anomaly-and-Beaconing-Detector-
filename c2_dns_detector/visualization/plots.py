"""
Visualization utilities for network threat detection.
Generates charts for interval distributions, jitter analysis, FFT spectrum,
DNS entropy vs query length, ROC curves, and confusion matrices.
"""

from pathlib import Path
from typing import List, Optional, Tuple, Union
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def set_plot_style():
    """Configure modern plot styling."""
    plt.rcParams["font.sans-serif"] = "DejaVu Sans"
    plt.rcParams["axes.edgecolor"] = "#cccccc"
    plt.rcParams["axes.linewidth"] = 0.8
    plt.rcParams["grid.color"] = "#e0e0e0"
    plt.rcParams["grid.linestyle"] = "--"
    plt.rcParams["grid.alpha"] = 0.6


def plot_interval_regularity_comparison(
    beacon_intervals: np.ndarray,
    benign_intervals: np.ndarray,
    beacon_label: str = "Cobalt Strike C2 Beacon",
    benign_label: str = "Benign Web Browsing",
    save_path: Optional[Union[str, Path]] = None,
) -> plt.Figure:
    """Plot inter-arrival time sequences and histograms comparing beaconing vs benign traffic."""
    set_plot_style()
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Subplot 1: Interval Timeline Sequence
    axes[0].plot(beacon_intervals, "o-", color="#d9534f", label=f"{beacon_label} (Regular + Jitter)", linewidth=1.5, markersize=5)
    axes[0].plot(benign_intervals[:len(beacon_intervals)], "s--", color="#337ab7", label=f"{benign_label} (Bursty)", linewidth=1.2, markersize=4, alpha=0.7)
    axes[0].set_title("Inter-Arrival Time (Delta-t) Sequence", fontsize=12, fontweight="bold")
    axes[0].set_xlabel("Connection Index (Flow #)", fontsize=10)
    axes[0].set_ylabel("Interval Delta-t (seconds)", fontsize=10)
    axes[0].grid(True)
    axes[0].legend(loc="upper right", frameon=True)

    # Subplot 2: Interval Distribution Density / Histogram
    axes[1].hist(beacon_intervals, bins=15, alpha=0.7, color="#d9534f", label=beacon_label, density=True)
    axes[1].hist(benign_intervals, bins=25, alpha=0.5, color="#337ab7", label=benign_label, density=True)
    axes[1].set_title("Interval Probability Density", fontsize=12, fontweight="bold")
    axes[1].set_xlabel("Interval Delta-t (seconds)", fontsize=10)
    axes[1].set_ylabel("Density", fontsize=10)
    axes[1].grid(True)
    axes[1].legend(loc="upper right", frameon=True)

    plt.tight_layout()
    if save_path:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
    return fig


def plot_fft_spectrum(
    intervals: np.ndarray,
    label: str = "C2 Beacon",
    save_path: Optional[Union[str, Path]] = None,
) -> plt.Figure:
    """Plot FFT power spectrum showing dominant periodic frequency concentration."""
    set_plot_style()
    fig, ax = plt.subplots(figsize=(8, 4.5))

    centered = intervals - np.mean(intervals)
    fft_vals = np.fft.rfft(centered)
    power = np.abs(fft_vals) ** 2
    freqs = np.fft.rfftfreq(len(centered))

    # Ignore DC bin
    ac_power = power[1:]
    ac_freqs = freqs[1:]
    norm_power = ac_power / (np.sum(ac_power) + 1e-9)

    ax.stem(ac_freqs, norm_power, linefmt="#d9534f-", markerfmt="#d9534f0", basefmt="k-")
    ax.set_title(f"Normalized FFT Power Spectrum: {label}", fontsize=12, fontweight="bold")
    ax.set_xlabel("Frequency (cycles / flow)", fontsize=10)
    ax.set_ylabel("Normalized Spectral Power", fontsize=10)
    ax.grid(True)

    plt.tight_layout()
    if save_path:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
    return fig


def plot_dns_entropy_distribution(
    dns_df: pd.DataFrame,
    entropy_threshold: float = 3.6,
    length_threshold: int = 35,
    save_path: Optional[Union[str, Path]] = None,
) -> plt.Figure:
    """Plot Shannon Entropy vs Query Length scatter plot with decision boundaries."""
    set_plot_style()
    fig, ax = plt.subplots(figsize=(10, 6))

    color_map = {
        "dnscat2": "#d9534f",
        "iodine": "#f0ad4e",
        "Cobalt Strike DNS Beacon": "#9b59b6",
        "BENIGN": "#337ab7",
    }

    tools = dns_df["tool"].unique() if "tool" in dns_df.columns else [("Tunnel" if x else "Benign") for x in dns_df["is_tunneling"]]

    for tool in tools:
        subset = dns_df[dns_df["tool"] == tool] if "tool" in dns_df.columns else dns_df
        color = color_map.get(tool, "#5bc0de")
        marker = "o" if tool != "BENIGN" else "^"
        alpha = 0.85 if tool != "BENIGN" else 0.4
        size = 50 if tool != "BENIGN" else 30
        ax.scatter(
            subset["query_length"],
            subset["shannon_entropy"],
            c=color,
            label=str(tool),
            alpha=alpha,
            s=size,
            marker=marker,
            edgecolors="none" if tool == "BENIGN" else "black",
            linewidth=0.5,
        )

    # Decision boundary lines
    ax.axhline(entropy_threshold, color="#e74c3c", linestyle="--", linewidth=1.5, label=f"Entropy Threshold ({entropy_threshold})")
    ax.axvline(length_threshold, color="#e67e22", linestyle=":", linewidth=1.5, label=f"Length Threshold ({length_threshold})")

    ax.set_title("DNS Tunneling Detection: Shannon Entropy vs Query Length", fontsize=12, fontweight="bold")
    ax.set_xlabel("Total Query Length (characters)", fontsize=10)
    ax.set_ylabel("Shannon Information Entropy (bits/char)", fontsize=10)
    ax.legend(loc="lower right", frameon=True)
    ax.grid(True)

    plt.tight_layout()
    if save_path:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
    return fig


def plot_confusion_matrix(
    tp: int,
    fp: int,
    tn: int,
    fn: int,
    title: str = "C2 Beaconing Detection Confusion Matrix",
    save_path: Optional[Union[str, Path]] = None,
) -> plt.Figure:
    """Plot an annotated confusion matrix heatmap."""
    set_plot_style()
    fig, ax = plt.subplots(figsize=(6, 5))

    matrix = np.array([[tn, fp], [fn, tp]])
    im = ax.imshow(matrix, cmap="Blues", interpolation="nearest")

    labels = [
        [f"TN\n{tn:,}\n(True Benign)", f"FP\n{fp:,}\n(False Alert)"],
        [f"FN\n{fn:,}\n(Missed Beacon)", f"TP\n{tp:,}\n(Detected Beacon)"],
    ]

    for i in range(2):
        for j in range(2):
            text_color = "white" if matrix[i, j] > (matrix.max() / 2) else "black"
            ax.text(j, i, labels[i][j], ha="center", va="center", color=text_color, fontsize=11, fontweight="bold")

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Predicted Benign", "Predicted Beacon"], fontsize=10)
    ax.set_yticklabels(["Actual Benign", "Actual Beacon"], fontsize=10)
    ax.set_title(title, fontsize=12, fontweight="bold")

    plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    plt.tight_layout()
    if save_path:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
    return fig


def plot_roc_curve(
    fprs: np.ndarray,
    tprs: np.ndarray,
    auc_score: float,
    operating_fpr: float = 0.0310,
    operating_tpr: float = 0.9200,
    title: str = "Receiver Operating Characteristic (ROC) Curve",
    save_path: Optional[Union[str, Path]] = None,
) -> plt.Figure:
    """Plot ROC curve with annotated benchmark operating point."""
    set_plot_style()
    fig, ax = plt.subplots(figsize=(7, 6))

    ax.plot(fprs, tprs, color="#2e6da4", linewidth=2.5, label=f"C2 Beacon Detector (AUC = {auc_score:.4f})")
    ax.plot([0, 1], [0, 1], color="#999999", linestyle="--", linewidth=1.2, label="Random Guess")

    # Mark Benchmark Operating Point (FPR=3.1%, TPR=92.0%)
    ax.scatter(
        [operating_fpr],
        [operating_tpr],
        color="#d9534f",
        s=120,
        zorder=5,
        edgecolor="black",
        linewidth=1.5,
        label=f"Benchmark Operating Point\n(Detection: {operating_tpr*100:.1f}%, FPR: {operating_fpr*100:.1f}%)",
    )

    ax.set_xlim([-0.02, 1.02])
    ax.set_ylim([-0.02, 1.05])
    ax.set_xlabel("False Positive Rate (FPR)", fontsize=10)
    ax.set_ylabel("True Positive Rate (Recall / TPR)", fontsize=10)
    ax.set_title(title, fontsize=12, fontweight="bold")
    ax.legend(loc="lower right", frameon=True)
    ax.grid(True)

    plt.tight_layout()
    if save_path:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
    return fig
