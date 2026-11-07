"""
Unit tests for C2 beaconing detection, interval regularity, and jitter analysis.
"""

import unittest
import numpy as np
import pandas as pd

from c2_dns_detector.detectors.beaconing import C2BeaconDetector, SessionFeatureExtractor


class TestBeaconingDetector(unittest.TestCase):
    def setUp(self):
        self.detector = C2BeaconDetector(min_flows=4, beacon_threshold=65.0)
        self.extractor = SessionFeatureExtractor(min_flows=4)

    def test_ideal_periodic_beacon(self):
        # 10 connections spaced exactly 60.0s apart
        timestamps = [1000.0 + i * 60.0 for i in range(10)]
        df_session = pd.DataFrame({
            "ts": timestamps,
            "orig_bytes": [450] * 10,
            "resp_bytes": [1200] * 10,
        })

        features = self.extractor.extract(df_session)
        self.assertIsNotNone(features)
        self.assertAlmostEqual(features["mean_interval_sec"], 60.0, places=2)
        self.assertAlmostEqual(features["cv_interval"], 0.0, places=2)
        self.assertAlmostEqual(features["norm_mad"], 0.0, places=2)

        score = self.detector.calculate_score(features)
        self.assertGreaterEqual(score, 90.0)

    def test_jittered_beacon(self):
        # 12 connections around 60.0s with 15% uniform jitter
        np.random.seed(42)
        timestamps = [1000.0]
        for _ in range(11):
            jittered_dt = 60.0 * (1.0 + np.random.uniform(-0.15, 0.15))
            timestamps.append(timestamps[-1] + jittered_dt)

        df_session = pd.DataFrame({
            "ts": timestamps,
            "orig_bytes": [450 + int(np.random.normal(0, 10)) for _ in range(12)],
            "resp_bytes": [1200 + int(np.random.normal(0, 20)) for _ in range(12)],
        })

        features = self.extractor.extract(df_session)
        self.assertIsNotNone(features)
        self.assertLess(features["cv_interval"], 0.20)
        self.assertLess(features["norm_mad"], 0.15)

        score = self.detector.calculate_score(features)
        self.assertGreaterEqual(score, 65.0)

    def test_bursty_web_traffic(self):
        # Bursty web traffic with high variance
        np.random.seed(42)
        timestamps = [1000.0]
        intervals = [0.2, 0.5, 120.0, 1.2, 340.0, 0.1, 45.0, 180.0]
        for dt in intervals:
            timestamps.append(timestamps[-1] + dt)

        df_session = pd.DataFrame({
            "ts": timestamps,
            "orig_bytes": [100, 4500, 200, 8500, 300, 120, 600, 1500, 200],
            "resp_bytes": [500, 45000, 1200, 68000, 1500, 400, 2400, 12000, 900],
        })

        features = self.extractor.extract(df_session)
        self.assertIsNotNone(features)
        self.assertGreater(features["cv_interval"], 1.0)

        score = self.detector.calculate_score(features)
        self.assertLess(score, 45.0)

    def test_sparse_session_ignored(self):
        # Only 2 connections - insufficient for beaconing detection
        df_session = pd.DataFrame({
            "ts": [1000.0, 1060.0],
            "orig_bytes": [100, 100],
            "resp_bytes": [200, 200],
        })
        features = self.extractor.extract(df_session)
        self.assertIsNone(features)


if __name__ == "__main__":
    unittest.main()
