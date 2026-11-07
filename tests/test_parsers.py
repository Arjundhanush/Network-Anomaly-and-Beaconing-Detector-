"""
Unit tests for Zeek conn.log and dns.log parsers.
"""

from pathlib import Path
import tempfile
import unittest
import pandas as pd

from c2_dns_detector.parsers.zeek_conn import parse_conn_log, ConnLogParser
from c2_dns_detector.parsers.zeek_dns import parse_dns_log, DnsLogParser


class TestZeekParsers(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_conn_tsv(self):
        tsv_content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\n"
            "1680000001.5\tC01\t192.168.1.10\t49152\t1.1.1.1\t443\ttcp\tssl\t0.25\t1200\t3500\n"
            "1680000061.5\tC02\t192.168.1.10\t49153\t1.1.1.1\t443\ttcp\tssl\t0.30\t1150\t3600\n"
            "#close\n"
        )
        conn_file = self.work_path / "conn.log"
        conn_file.write_text(tsv_content, encoding="utf-8")

        df = parse_conn_log(conn_file)
        self.assertEqual(len(df), 2)
        self.assertEqual(df.iloc[0]["id.orig_h"], "192.168.1.10")
        self.assertEqual(df.iloc[0]["id.resp_p"], 443)
        self.assertEqual(df.iloc[0]["orig_bytes"], 1200)

    def test_parse_conn_json(self):
        json_content = (
            '{"ts": 1680000001.0, "uid": "C01", "id.orig_h": "10.0.0.5", "id.orig_p": 50000, "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp", "duration": 0.05, "orig_bytes": 45, "resp_bytes": 120}\n'
            '{"ts": 1680000010.0, "uid": "C02", "id.orig_h": "10.0.0.5", "id.orig_p": 50001, "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp", "duration": 0.04, "orig_bytes": 45, "resp_bytes": 110}\n'
        )
        conn_file = self.work_path / "conn.json"
        conn_file.write_text(json_content, encoding="utf-8")

        df = parse_conn_log(conn_file)
        self.assertEqual(len(df), 2)
        self.assertEqual(df.iloc[1]["id.orig_h"], "10.0.0.5")
        self.assertEqual(df.iloc[1]["id.resp_p"], 53)

    def test_parse_dns_tsv(self):
        dns_content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\n"
            "1680000001.0\tD01\t10.0.0.5\t50000\t8.8.8.8\t53\tudp\t1234\t0.02\twww.google.com\t1\tC_INTERNET\t1\tA\t0\tNOERROR\n"
            "1680000005.0\tD02\t10.0.0.5\t50001\t8.8.8.8\t53\tudp\t1235\t0.03\tabcdef0123456789.tunnel.com\t1\tC_INTERNET\t16\tTXT\t0\tNOERROR\n"
        )
        dns_file = self.work_path / "dns.log"
        dns_file.write_text(dns_content, encoding="utf-8")

        df = parse_dns_log(dns_file)
        self.assertEqual(len(df), 2)
        self.assertEqual(df.iloc[0]["query"], "www.google.com")
        self.assertEqual(df.iloc[1]["qtype_name"], "TXT")


if __name__ == "__main__":
    unittest.main()
