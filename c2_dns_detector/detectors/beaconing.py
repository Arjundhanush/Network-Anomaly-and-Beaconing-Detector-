"""
C2 Beaconing Detector using interval regularity, jitter analysis, and FFT spectral concentration.
Analyzes Zeek conn.log network sessions to detect periodic malware callbacks (Cobalt Strike, Emotet, etc.).
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd


@dataclass
class BeaconResult:
    """Detection results and behavioral metrics for a network session."""
    orig_h: str
    resp_h: str
    resp_p: int
    proto: str
    flow_count: int
    total_duration_sec: float
    mean_interval_sec: float
    median_interval_sec: float
    std_interval_sec: float
    cv_interval: float              # Coefficient of Variation (std / mean)
    mad_interval_sec: float         # Median Absolute Deviation
    norm_mad: float                 # MAD / median
    jitter_ratio: float             # (max - min) / (2 * median)
    consec_jitter: float            # Mean relative consecutive interval change
    fft_spectral_peak: float        # Peak concentration in FFT frequency spectrum
    orig_bytes_mean: float
    orig_bytes_std: float
    resp_bytes_mean: float
    resp_bytes_std: float
    beacon_score: float             # Composite score [0 - 100]
    is_beacon: bool                 # Binary classification
    threat_confidence: str          # LOW, MEDIUM, HIGH, CRITICAL

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SessionFeatureExtractor:
    """Extracts temporal, statistical, and payload regularity features from a session flow."""

    def __init__(self, min_flows: int = 4):
        self.min_flows = min_flows

    def extract(self, df_session: pd.DataFrame) -> Optional[Dict[str, float]]:
        """
        Extract behavioral regularity features for a single session group.
        
        Args:
            df_session: DataFrame containing rows for one (orig_h, resp_h, resp_p, proto) session.

        Returns:
            Dictionary of extracted features, or None if flow count is below min_flows.
        """
        n_flows = len(df_session)
        if n_flows < self.min_flows:
            return None

        # Sort chronologically by connection timestamp
        timestamps = np.sort(df_session["ts"].to_numpy(dtype=float))
        intervals = np.diff(timestamps)

        # Remove negative or zero intervals caused by simultaneous socket opens
        intervals = intervals[intervals > 0.05]
        if len(intervals) < (self.min_flows - 1):
            return None

        mean_interval = float(np.mean(intervals))
        std_interval = float(np.std(intervals, ddof=1)) if len(intervals) > 1 else 0.0
        median_interval = float(np.median(intervals))

        # Coefficient of variation (CV = std / mean)
        cv = std_interval / (mean_interval + 1e-7)

        # Median Absolute Deviation (MAD)
        mad = float(np.median(np.abs(intervals - median_interval)))
        norm_mad = mad / (median_interval + 1e-7)

        # Jitter metrics
        min_int = float(np.min(intervals))
        max_int = float(np.max(intervals))
        jitter_ratio = (max_int - min_int) / (2.0 * median_interval + 1e-7)

        if len(intervals) > 1:
            consec_diffs = np.abs(np.diff(intervals))
            consec_jitter = float(np.mean(consec_diffs) / (median_interval + 1e-7))
        else:
            consec_jitter = 0.0

        # FFT Power Spectral Density concentration
        fft_peak = self._calculate_fft_peak(intervals)

        # Byte statistics
        orig_bytes = df_session["orig_bytes"].to_numpy(dtype=float) if "orig_bytes" in df_session else np.zeros(n_flows)
        resp_bytes = df_session["resp_bytes"].to_numpy(dtype=float) if "resp_bytes" in df_session else np.zeros(n_flows)

        total_duration = float(timestamps[-1] - timestamps[0])

        return {
            "flow_count": n_flows,
            "total_duration_sec": round(total_duration, 2),
            "mean_interval_sec": round(mean_interval, 3),
            "median_interval_sec": round(median_interval, 3),
            "std_interval_sec": round(std_interval, 3),
            "cv_interval": round(cv, 4),
            "mad_interval_sec": round(mad, 3),
            "norm_mad": round(norm_mad, 4),
            "jitter_ratio": round(jitter_ratio, 4),
            "consec_jitter": round(consec_jitter, 4),
            "fft_spectral_peak": round(fft_peak, 4),
            "orig_bytes_mean": round(float(np.mean(orig_bytes)), 1),
            "orig_bytes_std": round(float(np.std(orig_bytes)), 1),
            "resp_bytes_mean": round(float(np.mean(resp_bytes)), 1),
            "resp_bytes_std": round(float(np.std(resp_bytes)), 1),
        }

    def _calculate_fft_peak(self, intervals: np.ndarray) -> float:
        """
        Compute normalized peak concentration in the interval power spectrum using rFFT.
        For periodic beacon signals, power is concentrated in the fundamental frequency bin.
        """
        if len(intervals) < 4:
            return 0.0

        # Zero-center intervals
        centered = intervals - np.mean(intervals)
        
        # Real FFT
        fft_vals = np.fft.rfft(centered)
        power_spectrum = np.abs(fft_vals) ** 2

        # Ignore DC component (bin 0)
        ac_power = power_spectrum[1:]
        total_ac = np.sum(ac_power)
        if total_ac <= 1e-9:
            return 1.0  # Perfectly flat zero-variance signal

        peak_power = float(np.max(ac_power))
        return float(peak_power / total_ac)


class C2BeaconDetector:
    """
    Detector for periodic and jittered Command & Control beaconing sessions.
    Evaluates interval regularity, jitter bounds, spectral peak concentration, and byte distributions.
    """

    def __init__(
        self,
        min_flows: int = 4,
        beacon_threshold: float = 65.0,
        max_cv: float = 0.45,
        max_nmad: float = 0.35,
    ):
        """
        Args:
            min_flows: Minimum number of connections required in a session to analyze.
            beacon_threshold: Score cutoff [0 - 100] above which session is flagged as C2 beacon.
            max_cv: Maximum Coefficient of Variation for high interval regularity score.
            max_nmad: Maximum Normalized MAD for high jitter compliance score.
        """
        self.min_flows = min_flows
        self.beacon_threshold = beacon_threshold
        self.max_cv = max_cv
        self.max_nmad = max_nmad
        self.extractor = SessionFeatureExtractor(min_flows=min_flows)

    def calculate_score(self, features: Dict[str, float]) -> float:
        """
        Calculate composite beaconing confidence score [0 - 100].

        The score integrates:
          - S_interval: Penalty as CV exceeds max_cv (regular sleep period)
          - S_jitter: Penalty as normalized MAD exceeds max_nmad (jitter bound)
          - S_fft: Reward for spectral concentration
          - S_persistence: Weighting for sustained callback count
          - S_bytes: Consistency of outbound payload sizes
        """
        cv = features["cv_interval"]
        nmad = features["norm_mad"]
        fft_peak = features["fft_spectral_peak"]
        n_flows = features["flow_count"]
        orig_mean = features["orig_bytes_mean"]
        orig_std = features["orig_bytes_std"]

        # Component 1: Interval Regularity (Weight: 35%)
        # CV < 0.10 => 100%, CV > max_cv => 0%
        s_interval = max(0.0, 1.0 - (cv / self.max_cv)) * 100.0

        # Component 2: Jitter Compliance (Weight: 25%)
        s_jitter = max(0.0, 1.0 - (nmad / self.max_nmad)) * 100.0

        # Component 3: FFT Periodicity Concentration (Weight: 15%)
        s_fft = min(1.0, fft_peak * 2.2) * 100.0

        # Component 4: Flow Persistence (Weight: 15%)
        # Full score at 10 or more recurring callbacks
        s_persistence = min(1.0, n_flows / 10.0) * 100.0

        # Component 5: Byte Size Regularity (Weight: 10%)
        # Fixed or narrow payload size indicates heartbeat/checkin
        byte_cv = orig_std / (orig_mean + 50.0)
        s_bytes = max(0.0, 1.0 - (byte_cv / 1.5)) * 100.0

        composite = (
            0.35 * s_interval +
            0.25 * s_jitter +
            0.15 * s_fft +
            0.15 * s_persistence +
            0.10 * s_bytes
        )
        return float(np.clip(composite, 0.0, 100.0))

    def analyze_session(
        self,
        orig_h: str,
        resp_h: str,
        resp_p: int,
        proto: str,
        df_session: pd.DataFrame
    ) -> Optional[BeaconResult]:
        """Analyze a single connection session."""
        features = self.extractor.extract(df_session)
        if features is None:
            return None

        score = self.calculate_score(features)
        is_beacon = score >= self.beacon_threshold

        if score >= 90.0:
            confidence = "CRITICAL"
        elif score >= 80.0:
            confidence = "HIGH"
        elif score >= 65.0:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return BeaconResult(
            orig_h=orig_h,
            resp_h=resp_h,
            resp_p=resp_p,
            proto=proto,
            flow_count=features["flow_count"],
            total_duration_sec=features["total_duration_sec"],
            mean_interval_sec=features["mean_interval_sec"],
            median_interval_sec=features["median_interval_sec"],
            std_interval_sec=features["std_interval_sec"],
            cv_interval=features["cv_interval"],
            mad_interval_sec=features["mad_interval_sec"],
            norm_mad=features["norm_mad"],
            jitter_ratio=features["jitter_ratio"],
            consec_jitter=features["consec_jitter"],
            fft_spectral_peak=features["fft_spectral_peak"],
            orig_bytes_mean=features["orig_bytes_mean"],
            orig_bytes_std=features["orig_bytes_std"],
            resp_bytes_mean=features["resp_bytes_mean"],
            resp_bytes_std=features["resp_bytes_std"],
            beacon_score=round(score, 2),
            is_beacon=is_beacon,
            threat_confidence=confidence,
        )

    def detect(self, conn_df: pd.DataFrame) -> List[BeaconResult]:
        """
        Analyze all sessions in a conn.log DataFrame and return detection results.
        
        Args:
            conn_df: DataFrame parsed from Zeek conn.log.

        Returns:
            List of BeaconResult objects for all eligible sessions.
        """
        if conn_df.empty:
            return []

        required_cols = {"id.orig_h", "id.resp_h", "id.resp_p", "proto", "ts"}
        if not required_cols.issubset(conn_df.columns):
            raise ValueError(f"conn_df missing required columns: {required_cols - set(conn_df.columns)}")

        results: List[BeaconResult] = []
        grouped = conn_df.groupby(["id.orig_h", "id.resp_h", "id.resp_p", "proto"])

        for (orig_h, resp_h, resp_p, proto), group in grouped:
            res = self.analyze_session(
                orig_h=str(orig_h),
                resp_h=str(resp_h),
                resp_p=int(resp_p),
                proto=str(proto),
                df_session=group,
            )
            if res is not None:
                results.append(res)

        # Sort descending by beacon_score
        results.sort(key=lambda r: r.beacon_score, reverse=True)
        return results

    def to_dataframe(self, results: List[BeaconResult]) -> pd.DataFrame:
        """Convert list of BeaconResult to pandas DataFrame."""
        if not results:
            return pd.DataFrame()
        return pd.DataFrame([r.to_dict() for r in results])
