"""
Command-Line Interface (CLI) for c2_dns_detector.
Provides commands to analyze Zeek conn.log for C2 beacons, dns.log for tunneling,
and execute benchmark evaluations.
"""

import argparse
import json
from pathlib import Path
import sys
from typing import List

import pandas as pd

from .detectors.beaconing import C2BeaconDetector
from .detectors.dns_tunneling import DnsTunnelDetector
from .evaluation.benchmark import BenchmarkRunner
from .parsers.zeek_conn import parse_conn_log
from .parsers.zeek_dns import parse_dns_log


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="c2-dns-detector",
        description="Network Threat Detection: C2 Beaconing (Interval Regularity & Jitter) and DNS Tunneling (Shannon Entropy)",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command 1: scan-beacon
    p_beacon = subparsers.add_parser("scan-beacon", help="Scan Zeek conn.log for C2 beaconing sessions")
    p_beacon.add_argument("--conn-log", "-c", required=True, type=Path, help="Path to Zeek conn.log")
    p_beacon.add_argument("--threshold", "-t", type=float, default=65.0, help="Beacon score threshold [0-100] (default: 65.0)")
    p_beacon.add_argument("--min-flows", "-m", type=int, default=4, help="Minimum flows per session (default: 4)")
    p_beacon.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    p_beacon.add_argument("--output", "-o", type=Path, help="Optional output file path")

    # Command 2: scan-dns
    p_dns = subparsers.add_parser("scan-dns", help="Scan Zeek dns.log for DNS tunneling queries")
    p_dns.add_argument("--dns-log", "-d", required=True, type=Path, help="Path to Zeek dns.log")
    p_dns.add_argument("--threshold", "-t", type=float, default=65.0, help="Tunnel score threshold [0-100] (default: 65.0)")
    p_dns.add_argument("--entropy", "-e", type=float, default=3.6, help="Shannon entropy threshold in bits/char (default: 3.6)")
    p_dns.add_argument("--aggregate", "-a", action="store_true", help="Aggregate alerts by parent domain")
    p_dns.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    p_dns.add_argument("--output", "-o", type=Path, help="Optional output file path")

    # Command 3: benchmark
    p_bench = subparsers.add_parser("benchmark", help="Run benchmark against CTU-13 and MTA dataset ground truth")
    p_bench.add_argument("--threshold", "-t", type=float, default=65.0, help="Beacon score threshold (default: 65.0)")
    p_bench.add_argument("--conn-log", type=Path, help="Optional custom conn.log")
    p_bench.add_argument("--dns-log", type=Path, help="Optional custom dns.log")

    return parser


def format_table(df: pd.DataFrame, max_cols: int = 10, max_rows: int = 25) -> str:
    """Format DataFrame as an ASCII terminal table."""
    if df.empty:
        return "No records found."
    pd.set_option("display.max_columns", max_cols)
    pd.set_option("display.width", 140)
    return df.head(max_rows).to_string(index=False)


def handle_scan_beacon(args):
    conn_path = Path(args.conn_log)
    if not conn_path.exists():
        print(f"[!] Error: conn.log file not found: {conn_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing Zeek conn.log: {conn_path}...")
    df_conn = parse_conn_log(conn_path)
    print(f"[*] Total connections parsed: {len(df_conn):,}")

    detector = C2BeaconDetector(min_flows=args.min_flows, beacon_threshold=args.threshold)
    results = detector.detect(df_conn)
    df_res = detector.to_dataframe(results)

    alerts = df_res[df_res["is_beacon"]] if not df_res.empty else pd.DataFrame()
    print(f"[+] Total sessions analyzed: {len(df_res)}")
    print(f"[+] Potential C2 Beacons flagged: {len(alerts)}")

    display_cols = [
        "orig_h", "resp_h", "resp_p", "proto", "flow_count",
        "median_interval_sec", "cv_interval", "jitter_ratio",
        "beacon_score", "threat_confidence"
    ]
    avail_cols = [c for c in display_cols if c in alerts.columns]

    if args.format == "table":
        if not alerts.empty:
            print("\n" + "=" * 80)
            print("                 C2 BEACONING DETECTION ALERTS")
            print("=" * 80)
            print(format_table(alerts[avail_cols]))
        else:
            print("[*] No beaconing sessions exceeded the alert threshold.")
    elif args.format == "json":
        output_str = json.dumps(alerts.to_dict(orient="records"), indent=2)
        if args.output:
            args.output.write_text(output_str, encoding="utf-8")
            print(f"[+] Results saved to {args.output}")
        else:
            print(output_str)
    elif args.format == "csv":
        if args.output:
            alerts.to_csv(args.output, index=False)
            print(f"[+] Results saved to {args.output}")
        else:
            print(alerts.to_csv(index=False))


def handle_scan_dns(args):
    dns_path = Path(args.dns_log)
    if not dns_path.exists():
        print(f"[!] Error: dns.log file not found: {dns_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing Zeek dns.log: {dns_path}...")
    df_dns = parse_dns_log(dns_path)
    print(f"[*] Total DNS queries parsed: {len(df_dns):,}")

    detector = DnsTunnelDetector(
        entropy_threshold=args.entropy,
        tunnel_score_threshold=args.threshold,
    )
    results = detector.detect(df_dns)

    if args.aggregate:
        df_agg = detector.aggregate_by_domain(results)
        print(f"[+] Domains analyzed: {len(df_agg)}")
        if args.format == "table":
            print("\n" + "=" * 80)
            print("             DNS TUNNELING - AGGREGATED DOMAIN ALERTS")
            print("=" * 80)
            print(format_table(df_agg))
        elif args.format == "json":
            out_str = json.dumps(df_agg.to_dict(orient="records"), indent=2)
            print(out_str)
        elif args.format == "csv":
            print(df_agg.to_csv(index=False))
        return

    df_res = detector.to_dataframe(results)
    alerts = df_res[df_res["is_tunneling"]] if not df_res.empty else pd.DataFrame()
    print(f"[+] Suspicious DNS Tunneling queries flagged: {len(alerts)}")

    display_cols = [
        "query", "parent_domain", "shannon_entropy", "query_length",
        "longest_label_length", "qtype", "tunnel_score", "threat_confidence"
    ]
    avail_cols = [c for c in display_cols if c in alerts.columns]

    if args.format == "table":
        if not alerts.empty:
            print("\n" + "=" * 80)
            print("                 DNS TUNNELING DETECTION ALERTS")
            print("=" * 80)
            print(format_table(alerts[avail_cols]))
        else:
            print("[*] No queries exceeded the tunneling threshold.")
    elif args.format == "json":
        out_str = json.dumps(alerts.to_dict(orient="records"), indent=2)
        print(out_str)
    elif args.format == "csv":
        print(alerts.to_csv(index=False))


def handle_benchmark(args):
    print("\n" + "=" * 60)
    print("      RUNNING BENCHMARK (CTU-13 & MTA DATASETS)")
    print("=" * 60)
    runner = BenchmarkRunner(
        conn_log_path=args.conn_log,
        dns_log_path=args.dns_log,
    )

    print("\n[+] Evaluating C2 Beaconing Engine...")
    metrics_beacon, df_beacon = runner.evaluate_c2_beaconing(beacon_threshold=args.threshold)
    metrics_beacon.print_summary()

    print("\n[+] Evaluating DNS Tunneling Engine...")
    metrics_dns, df_dns = runner.evaluate_dns_tunneling(tunnel_threshold=args.threshold)
    metrics_dns.print_summary()


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan-beacon":
        handle_scan_beacon(args)
    elif args.command == "scan-dns":
        handle_scan_dns(args)
    elif args.command == "benchmark":
        handle_benchmark(args)


if __name__ == "__main__":
    main()
