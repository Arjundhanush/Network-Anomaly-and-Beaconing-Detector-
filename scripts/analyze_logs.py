"""
Analyze arbitrary Zeek logs (conn.log or dns.log) and display threat detections.
"""

import argparse
from pathlib import Path
import sys

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from c2_dns_detector.detectors.beaconing import C2BeaconDetector
from c2_dns_detector.detectors.dns_tunneling import DnsTunnelDetector
from c2_dns_detector.parsers.zeek_conn import parse_conn_log
from c2_dns_detector.parsers.zeek_dns import parse_dns_log


def main():
    parser = argparse.ArgumentParser(description="Analyze Zeek network logs for C2 Beacons and DNS Tunneling.")
    parser.add_argument("--conn-log", type=Path, help="Path to Zeek conn.log")
    parser.add_argument("--dns-log", type=Path, help="Path to Zeek dns.log")
    parser.add_argument("--beacon-threshold", type=float, default=65.0, help="Beacon alert threshold [0-100]")
    parser.add_argument("--dns-threshold", type=float, default=65.0, help="DNS tunnel alert threshold [0-100]")
    args = parser.parse_args()

    if not args.conn_log and not args.dns_log:
        parser.print_help()
        sys.exit(1)

    if args.conn_log:
        print(f"\n[*] Scanning conn.log: {args.conn_log}")
        df_conn = parse_conn_log(args.conn_log)
        detector = C2BeaconDetector(beacon_threshold=args.beacon_threshold)
        results = detector.detect(df_conn)
        df_res = detector.to_dataframe(results)
        alerts = df_res[df_res["is_beacon"]] if not df_res.empty else df_res

        print(f"[+] Total sessions analyzed: {len(df_res)}")
        print(f"[!] Flagged C2 Beacon sessions: {len(alerts)}")
        if not alerts.empty:
            cols = ["orig_h", "resp_h", "resp_p", "proto", "flow_count", "median_interval_sec", "cv_interval", "jitter_ratio", "beacon_score", "threat_confidence"]
            print(alerts[cols].head(20).to_string(index=False))

    if args.dns_log:
        print(f"\n[*] Scanning dns.log: {args.dns_log}")
        df_dns = parse_dns_log(args.dns_log)
        detector = DnsTunnelDetector(tunnel_score_threshold=args.dns_threshold)
        results = detector.detect(df_dns)
        df_agg = detector.aggregate_by_domain(results)
        tunnel_domains = df_agg[df_agg["is_tunnel_domain"]] if not df_agg.empty else df_agg

        print(f"[+] Total DNS queries parsed: {len(df_dns)}")
        print(f"[!] Suspected Tunneling Domains: {len(tunnel_domains)}")
        if not tunnel_domains.empty:
            print(tunnel_domains.to_string(index=False))


if __name__ == "__main__":
    main()
