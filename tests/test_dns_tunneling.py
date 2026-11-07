"""
Unit tests for DNS tunneling detection (Shannon entropy & query-length features).
"""

import unittest
from c2_dns_detector.detectors.dns_tunneling import DnsTunnelDetector


class TestDnsTunnelingDetector(unittest.TestCase):
    def setUp(self):
        self.detector = DnsTunnelDetector()

    def test_shannon_entropy_calculation(self):
        # Uniform character string: high entropy
        high_entropy_str = "abcdefghijklmnopqrstuvwxyz0123456789"
        entropy_high = self.detector.calculate_shannon_entropy(high_entropy_str)
        self.assertGreater(entropy_high, 4.5)

        # Monotonous repetitive string: low entropy
        low_entropy_str = "aaaaaaaaaaaaaaaaaaaaa"
        entropy_low = self.detector.calculate_shannon_entropy(low_entropy_str)
        self.assertEqual(entropy_low, 0.0)

        # Natural English label: medium entropy
        normal_str = "microsoft"
        entropy_normal = self.detector.calculate_shannon_entropy(normal_str)
        self.assertGreater(entropy_normal, 2.5)
        self.assertLess(entropy_normal, 3.5)

    def test_dnscat2_tunnel_detection(self):
        # Long hex-encoded payload under custom domain
        dnscat_query = "0123456789abcdef0123456789abcdef0123456789abcdef.dnscat.tunnel-target.org"
        result = self.detector.score_query(dnscat_query, qtype="TXT")

        self.assertTrue(result.is_tunneling)
        self.assertGreaterEqual(result.tunnel_score, 75.0)
        self.assertGreaterEqual(result.longest_label_length, 45)
        self.assertGreaterEqual(result.shannon_entropy, 3.6)

    def test_benign_domain_not_flagged(self):
        benign_query = "mail.google.com"
        result = self.detector.score_query(benign_query, qtype="A")

        self.assertFalse(result.is_tunneling)
        self.assertLess(result.tunnel_score, 40.0)

    def test_cdn_whitelist_dampening(self):
        # High entropy-looking CDN subdomain should be dampened
        cdn_query = "d3m7h8e2a1b9.cloudfront.net"
        result = self.detector.score_query(cdn_query, qtype="A")
        self.assertFalse(result.is_tunneling)


if __name__ == "__main__":
    unittest.main()
