"""
Integration and regression test for the CTU-13 / MTA benchmark results.
Verifies:
  - 92.0% C2 Beaconing Detection (23 of 25 beacon sessions)
  - 3.1% False Positive Rate (62 of 2,000 benign connections)
"""

from pathlib import Path
import unittest

from c2_dns_detector.evaluation.benchmark import BenchmarkRunner


class TestBenchmarkAccuracy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = BenchmarkRunner()

    def test_c2_beaconing_benchmark_metrics(self):
        metrics, df = self.runner.evaluate_c2_beaconing(beacon_threshold=65.0)

        # Exact ground truth totals
        self.assertEqual(metrics.positives, 25, "Expected 25 beaconing sessions")
        self.assertEqual(metrics.negatives, 2000, "Expected 2,000 benign connections")

        # Exact True Positives and False Positives
        self.assertEqual(metrics.true_positives, 23, "Expected 23 of 25 beacon sessions detected")
        self.assertEqual(metrics.false_negatives, 2, "Expected 2 false negatives")
        self.assertEqual(metrics.false_positives, 62, "Expected 62 false positives")
        self.assertEqual(metrics.true_negatives, 1938, "Expected 1,938 true negatives")

        # Exact Rates
        self.assertAlmostEqual(metrics.detection_rate, 0.9200, places=4, msg="Detection rate must be 92.0%")
        self.assertAlmostEqual(metrics.false_positive_rate, 0.0310, places=4, msg="False positive rate must be 3.10%")

    def test_dns_tunneling_benchmark_metrics(self):
        metrics, df = self.runner.evaluate_dns_tunneling(tunnel_threshold=65.0)
        self.assertEqual(metrics.positives, 120)
        self.assertEqual(metrics.negatives, 350)
        self.assertEqual(metrics.true_positives, 120)
        self.assertEqual(metrics.false_positives, 0)
        self.assertEqual(metrics.detection_rate, 1.0)


if __name__ == "__main__":
    unittest.main()
