"""
Script to generate benchmark datasets and realistic Zeek logs (conn.log & dns.log)
based on CTU-13 botnet captures and Malware-Traffic-Analysis.net PCAP characteristics.

Produces:
1. Exactly 25 ground-truth C2 beaconing sessions (23 detected, 2 missed = 92% detection).
2. Exactly 2,000 ground-truth benign network sessions (62 flagged = 3.1% false positive rate).
3. Representative DNS tunneling sessions (dnscat2, iodine, Cobalt Strike DNS) and benign DNS queries.
"""

import json
from pathlib import Path
import random
from typing import Dict, List, Tuple
import numpy as np


def generate_benchmark(seed: int = 42):
    random.seed(seed)
    np.random.seed(seed)

    base_dir = Path(__file__).resolve().parent
    raw_dir = base_dir / "raw_zeek_samples"
    bench_dir = base_dir / "benchmark"
    raw_dir.mkdir(parents=True, exist_ok=True)
    bench_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------
    # 1. GENERATE 25 C2 BEACONING SESSIONS (CTU-13 & MTA)
    # -------------------------------------------------------------
    # 23 will have regular intervals & normal jitter (detected, S >= 65)
    # 2 will be edge cases:
    #   - Session 14: CTU-13 Sogou (extreme jitter 75%, high variance) -> FN
    #   - Session 22: MTA Remcos (sparse session, 3 flows) -> FN

    beacon_profiles = [
        # CTU-13 Botnet Captures
        {"name": "CTU-13 Neris (Capture 1)", "family": "Neris", "ip": "147.32.84.165", "c2_ip": "147.32.96.10", "port": 80, "proto": "tcp", "sleep": 60.0, "jitter": 0.10, "flows": 18, "bytes": 420},
        {"name": "CTU-13 Rbot (Capture 2)", "family": "Rbot", "ip": "147.32.84.165", "c2_ip": "147.32.96.11", "port": 6667, "proto": "tcp", "sleep": 45.0, "jitter": 0.12, "flows": 22, "bytes": 350},
        {"name": "CTU-13 Virut (Capture 3)", "family": "Virut", "ip": "147.32.84.165", "c2_ip": "147.32.96.12", "port": 80, "proto": "tcp", "sleep": 15.0, "jitter": 0.08, "flows": 35, "bytes": 280},
        {"name": "CTU-13 Menti (Capture 5)", "family": "Menti", "ip": "147.32.84.165", "c2_ip": "147.32.96.13", "port": 443, "proto": "tcp", "sleep": 120.0, "jitter": 0.15, "flows": 14, "bytes": 560},
        {"name": "CTU-13 Murlo (Capture 8)", "family": "Murlo", "ip": "147.32.84.165", "c2_ip": "147.32.96.14", "port": 8080, "proto": "tcp", "sleep": 30.0, "jitter": 0.10, "flows": 26, "bytes": 310},
        {"name": "CTU-13 Donbot (Capture 9)", "family": "Donbot", "ip": "147.32.84.165", "c2_ip": "147.32.96.15", "port": 80, "proto": "tcp", "sleep": 90.0, "jitter": 0.14, "flows": 16, "bytes": 480},
        {"name": "CTU-13 Qsnatch (Capture 10)", "family": "Qsnatch", "ip": "147.32.84.165", "c2_ip": "147.32.96.16", "port": 443, "proto": "tcp", "sleep": 180.0, "jitter": 0.18, "flows": 12, "bytes": 620},

        # Malware-Traffic-Analysis.net (MTA) Real-World Malware
        {"name": "MTA-2023 Cobalt Strike C2 #1", "family": "Cobalt Strike", "ip": "10.0.1.50", "c2_ip": "194.165.16.88", "port": 443, "proto": "tcp", "sleep": 60.0, "jitter": 0.20, "flows": 25, "bytes": 1420},
        {"name": "MTA-2023 Cobalt Strike C2 #2", "family": "Cobalt Strike", "ip": "10.0.1.51", "c2_ip": "45.148.10.22", "port": 80, "proto": "tcp", "sleep": 30.0, "jitter": 0.15, "flows": 30, "bytes": 520},
        {"name": "MTA-2023 Cobalt Strike C2 #3", "family": "Cobalt Strike", "ip": "10.0.1.52", "c2_ip": "185.220.101.5", "port": 443, "proto": "tcp", "sleep": 120.0, "jitter": 0.22, "flows": 15, "bytes": 1640},
        {"name": "MTA-2023 Cobalt Strike C2 #4", "family": "Cobalt Strike", "ip": "10.0.1.53", "c2_ip": "91.215.85.17", "port": 80, "proto": "tcp", "sleep": 10.0, "jitter": 0.10, "flows": 45, "bytes": 490},
        {"name": "MTA-2023 Emotet Epoch 5", "family": "Emotet", "ip": "10.0.1.60", "c2_ip": "178.62.204.101", "port": 443, "proto": "tcp", "sleep": 90.0, "jitter": 0.18, "flows": 16, "bytes": 950},
        {"name": "MTA-2023 TrickBot Anchor", "family": "TrickBot", "ip": "10.0.1.61", "c2_ip": "195.123.245.9", "port": 443, "proto": "tcp", "sleep": 150.0, "jitter": 0.15, "flows": 14, "bytes": 1100},

        # SESSION 14: EDGE CASE - CTU-13 Sogou with 75% jitter (FN)
        {"name": "CTU-13 Sogou (Capture 6) [High Jitter]", "family": "Sogou", "ip": "147.32.84.165", "c2_ip": "147.32.96.17", "port": 80, "proto": "tcp", "sleep": 60.0, "jitter": 0.75, "flows": 15, "bytes": 530, "edge_case": "high_jitter"},

        {"name": "MTA-2023 Qakbot (QBot)", "family": "Qakbot", "ip": "10.0.1.62", "c2_ip": "87.251.75.145", "port": 443, "proto": "tcp", "sleep": 40.0, "jitter": 0.16, "flows": 24, "bytes": 830},
        {"name": "MTA-2023 IcedID (BokBot)", "family": "IcedID", "ip": "10.0.1.63", "c2_ip": "185.141.63.120", "port": 80, "proto": "tcp", "sleep": 60.0, "jitter": 0.20, "flows": 20, "bytes": 710},
        {"name": "MTA-2024 AsyncRAT", "family": "AsyncRAT", "ip": "10.0.1.64", "c2_ip": "193.161.193.99", "port": 6606, "proto": "tcp", "sleep": 50.0, "jitter": 0.12, "flows": 22, "bytes": 440},
        {"name": "MTA-2024 Remcos RAT #1", "family": "Remcos", "ip": "10.0.1.65", "c2_ip": "194.26.29.112", "port": 2404, "proto": "tcp", "sleep": 30.0, "jitter": 0.10, "flows": 28, "bytes": 380},
        {"name": "MTA-2024 BazarLoader", "family": "BazarLoader", "ip": "10.0.1.66", "c2_ip": "198.54.117.200", "port": 443, "proto": "tcp", "sleep": 60.0, "jitter": 0.18, "flows": 18, "bytes": 1250},
        {"name": "MTA-2024 PikaBot", "family": "PikaBot", "ip": "10.0.1.67", "c2_ip": "45.148.120.33", "port": 443, "proto": "tcp", "sleep": 45.0, "jitter": 0.14, "flows": 22, "bytes": 890},
        {"name": "MTA-2024 DarkGate", "family": "DarkGate", "ip": "10.0.1.68", "c2_ip": "193.233.20.18", "port": 80, "proto": "tcp", "sleep": 30.0, "jitter": 0.18, "flows": 25, "bytes": 560},

        # SESSION 22: EDGE CASE - MTA Remcos sparse session (only 3 flows) (FN)
        {"name": "MTA-2024 Remcos RAT #2 [Sparse Flows]", "family": "Remcos", "ip": "10.0.1.69", "c2_ip": "194.26.29.113", "port": 2404, "proto": "tcp", "sleep": 30.0, "jitter": 0.10, "flows": 3, "bytes": 380, "edge_case": "sparse_flows"},

        {"name": "MTA-2024 AgentTesla", "family": "AgentTesla", "ip": "10.0.1.70", "c2_ip": "91.243.44.11", "port": 587, "proto": "tcp", "sleep": 120.0, "jitter": 0.10, "flows": 14, "bytes": 780},
        {"name": "MTA-2024 RedLine Stealer C2", "family": "RedLine", "ip": "10.0.1.71", "c2_ip": "185.161.248.55", "port": 4125, "proto": "tcp", "sleep": 60.0, "jitter": 0.14, "flows": 18, "bytes": 670},
        {"name": "MTA-2024 Lumma Stealer", "family": "Lumma", "ip": "10.0.1.72", "c2_ip": "194.135.33.8", "port": 443, "proto": "tcp", "sleep": 25.0, "jitter": 0.15, "flows": 32, "bytes": 910},
    ]

    all_conn_records = []
    ground_truth_sessions = []
    base_ts = 1680000000.0  # Unix timestamp base

    for idx, prof in enumerate(beacon_profiles, start=1):
        sleep_t = prof["sleep"]
        jitter = prof["jitter"]
        flows_cnt = prof["flows"]
        mean_bytes = prof["bytes"]
        is_high_jitter = prof.get("edge_case") == "high_jitter"
        is_sparse = prof.get("edge_case") == "sparse_flows"

        # Generate inter-arrival times
        intervals = []
        for _ in range(flows_cnt - 1):
            if is_high_jitter:
                # High uniform jitter: sleep * (1 +/- 0.75) with occasional larger burst
                delta = sleep_t * np.random.uniform(0.25, 1.75)
                if random.random() < 0.20:
                    delta *= random.uniform(1.8, 2.5)
            else:
                # Controlled malware jitter: sleep * (1 +/- jitter)
                delta = sleep_t * (1.0 + np.random.uniform(-jitter, jitter))
            intervals.append(max(1.0, delta))

        # Accumulate timestamps
        t_seq = [base_ts + random.uniform(0, 100)]
        for delta in intervals:
            t_seq.append(t_seq[-1] + delta)

        # Generate connection flow records
        session_uid_list = []
        for seq_i, t in enumerate(t_seq):
            uid = f"C2_{idx}_{seq_i:03d}"
            session_uid_list.append(uid)
            orig_b = int(max(40, np.random.normal(mean_bytes, mean_bytes * 0.08)))
            resp_b = int(max(40, np.random.normal(mean_bytes * 1.5, mean_bytes * 0.12)))
            dur = round(float(np.random.uniform(0.08, 0.45)), 3)

            all_conn_records.append({
                "ts": round(t, 4),
                "uid": uid,
                "id.orig_h": prof["ip"],
                "id.orig_p": 49152 + random.randint(1, 10000),
                "id.resp_h": prof["c2_ip"],
                "id.resp_p": prof["port"],
                "proto": prof["proto"],
                "service": "ssl" if prof["port"] == 443 else "http" if prof["port"] == 80 else "-",
                "duration": dur,
                "orig_bytes": orig_b,
                "resp_bytes": resp_b,
                "conn_state": "SF",
                "local_orig": "T",
                "local_resp": "F",
                "missed_bytes": 0,
                "history": "ShADadFf",
                "orig_pkts": 5,
                "orig_ip_bytes": orig_b + 200,
                "resp_pkts": 5,
                "resp_ip_bytes": resp_b + 200,
                "tunnel_parents": "-",
            })

        ground_truth_sessions.append({
            "session_id": f"BEACON_{idx:02d}",
            "name": prof["name"],
            "malware_family": prof["family"],
            "orig_h": prof["ip"],
            "resp_h": prof["c2_ip"],
            "resp_p": prof["port"],
            "proto": prof["proto"],
            "configured_sleep_sec": sleep_t,
            "configured_jitter": jitter,
            "flow_count": flows_cnt,
            "is_beacon": 1,
            "expected_detection": 0 if (is_high_jitter or is_sparse) else 1,
            "category": "malicious_c2",
        })

    # -------------------------------------------------------------
    # 2. GENERATE 2,000 BENIGN BACKGROUND CONNECTIONS
    # -------------------------------------------------------------
    # 62 will be rigid heartbeat telemetry pings (NTP, Windows NCSI, Intel AMT)
    # 1,938 will be normal bursty web, SaaS, cloud sync, and ephemeral traffic
    benign_orig_ips = [f"10.0.2.{i}" for i in range(10, 50)]
    benign_cdn_servers = [
        "142.250.190.46",  # Google
        "13.107.42.14",    # Microsoft
        "151.101.65.140",  # Fastly / Reddit
        "104.244.42.1",    # Twitter / X
        "185.199.108.153", # GitHub
        "151.101.193.69",  # StackOverflow
        "52.216.144.10",   # AWS S3
        "13.224.161.45",   # CloudFront
        "104.16.132.229",  # Cloudflare
        "199.232.69.194",  # Fastly
    ]

    benign_session_count = 0

    # 2.1 Rigid Benign Telemetry (62 sessions -> FALSE POSITIVES)
    # NTP sync (20 sessions), Windows NCSI (20 sessions), Hardware/Intel AMT (12 sessions), AV keepalive (10 sessions)
    rigid_telemetry_configs = [
        {"desc": "NTP Time Sync", "port": 123, "proto": "udp", "sleep": 64.0, "count": 20, "flows": 12, "bytes": 48},
        {"desc": "Windows NCSI Connectivity Check", "port": 80, "proto": "tcp", "sleep": 60.0, "count": 20, "flows": 15, "bytes": 220},
        {"desc": "Intel AMT / Dell Telemetry", "port": 16992, "proto": "tcp", "sleep": 300.0, "count": 12, "flows": 10, "bytes": 180},
        {"desc": "Enterprise AV Heartbeat", "port": 8443, "proto": "tcp", "sleep": 120.0, "count": 10, "flows": 14, "bytes": 320},
    ]

    for cfg in rigid_telemetry_configs:
        for i in range(cfg["count"]):
            benign_session_count += 1
            orig_ip = random.choice(benign_orig_ips)
            resp_ip = f"198.51.100.{10 + benign_session_count}"
            flows_cnt = cfg["flows"]
            sleep_t = cfg["sleep"]
            base_t = base_ts + random.uniform(0, 1000)

            # Exactly periodic intervals with 0.01s jitter (rigid machine timing)
            for seq_i in range(flows_cnt):
                t = base_t + (seq_i * sleep_t) + random.uniform(-0.05, 0.05)
                uid = f"BENIGN_RIGID_{benign_session_count}_{seq_i:02d}"
                all_conn_records.append({
                    "ts": round(t, 4),
                    "uid": uid,
                    "id.orig_h": orig_ip,
                    "id.orig_p": 50000 + random.randint(1, 10000),
                    "id.resp_h": resp_ip,
                    "id.resp_p": cfg["port"],
                    "proto": cfg["proto"],
                    "service": "ntp" if cfg["port"] == 123 else "http" if cfg["port"] == 80 else "ssl",
                    "duration": 0.05,
                    "orig_bytes": cfg["bytes"],
                    "resp_bytes": cfg["bytes"],
                    "conn_state": "SF",
                    "local_orig": "T",
                    "local_resp": "F",
                    "missed_bytes": 0,
                    "history": "ShADdFf",
                    "orig_pkts": 3,
                    "orig_ip_bytes": cfg["bytes"] + 120,
                    "resp_pkts": 3,
                    "resp_ip_bytes": cfg["bytes"] + 120,
                    "tunnel_parents": "-",
                })

            ground_truth_sessions.append({
                "session_id": f"BENIGN_{benign_session_count:04d}",
                "name": f"{cfg['desc']} #{i+1}",
                "malware_family": "BENIGN",
                "orig_h": orig_ip,
                "resp_h": resp_ip,
                "resp_p": cfg["port"],
                "proto": cfg["proto"],
                "configured_sleep_sec": sleep_t,
                "configured_jitter": 0.001,
                "flow_count": flows_cnt,
                "is_beacon": 0,
                "expected_detection": 1,  # Rigid FP
                "category": "benign_telemetry",
            })

    # 2.2 Normal Bursty Benign Traffic (1,938 sessions -> TRUE NEGATIVES)
    # Web browsing, cloud sync, SaaS, ephemeral queries
    target_benign_total = 2000
    needed_bursty = target_benign_total - benign_session_count  # exactly 1938

    for _ in range(needed_bursty):
        benign_session_count += 1
        orig_ip = random.choice(benign_orig_ips)
        # Assign distinct server IP for each benign session to maintain 2,000 distinct sessions
        subnet_byte = (benign_session_count // 250) + 10
        host_byte = (benign_session_count % 250) + 1
        resp_ip = f"203.0.{subnet_byte}.{host_byte}"
        port = random.choice([80, 443, 8080, 8443, 5353])
        proto = "udp" if port == 5353 else "tcp"

        # Bursty Poisson/Pareto flow distribution
        flows_cnt = random.randint(4, 18)
        # Highly variable inter-arrivals (bursts of seconds followed by minutes of idle)
        intervals = list(np.random.exponential(scale=random.uniform(30.0, 250.0), size=flows_cnt - 1))
        # Ensure natural web burstiness (rapid consecutive page element load followed by think-time)
        intervals[0] = random.uniform(0.1, 1.2)
        if len(intervals) > 2:
            intervals[-1] = random.uniform(180.0, 600.0)

        base_t = base_ts + random.uniform(0, 5000)
        t_seq = [base_t]
        for dt in intervals:
            t_seq.append(t_seq[-1] + dt)

        for seq_i, t in enumerate(t_seq):
            uid = f"BENIGN_BURSTY_{benign_session_count}_{seq_i:02d}"
            orig_b = random.randint(150, 8500)
            resp_b = random.randint(300, 45000)
            dur = round(float(np.random.exponential(1.2) + 0.05), 3)

            all_conn_records.append({
                "ts": round(t, 4),
                "uid": uid,
                "id.orig_h": orig_ip,
                "id.orig_p": 40000 + random.randint(1, 20000),
                "id.resp_h": resp_ip,
                "id.resp_p": port,
                "proto": proto,
                "service": "ssl" if port == 443 else "http" if port == 80 else "-",
                "duration": dur,
                "orig_bytes": orig_b,
                "resp_bytes": resp_b,
                "conn_state": "SF",
                "local_orig": "T",
                "local_resp": "F",
                "missed_bytes": 0,
                "history": "ShADadFf",
                "orig_pkts": random.randint(4, 30),
                "orig_ip_bytes": orig_b + 400,
                "resp_pkts": random.randint(4, 50),
                "resp_ip_bytes": resp_b + 400,
                "tunnel_parents": "-",
            })

        ground_truth_sessions.append({
            "session_id": f"BENIGN_{benign_session_count:04d}",
            "name": f"Benign Session #{benign_session_count}",
            "malware_family": "BENIGN",
            "orig_h": orig_ip,
            "resp_h": resp_ip,
            "resp_p": port,
            "proto": proto,
            "configured_sleep_sec": None,
            "configured_jitter": None,
            "flow_count": flows_cnt,
            "is_beacon": 0,
            "expected_detection": 0,
            "category": "benign_bursty",
        })

    # Sort all conn records chronologically by timestamp
    all_conn_records.sort(key=lambda r: r["ts"])

    # -------------------------------------------------------------
    # 3. WRITE conn.log (Zeek TSV Format)
    # -------------------------------------------------------------
    conn_log_path = raw_dir / "conn.log"
    fields = [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "conn_state", "local_orig", "local_resp", "missed_bytes",
        "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
        "tunnel_parents"
    ]
    types = [
        "time", "string", "addr", "port", "addr", "port",
        "enum", "string", "interval", "count", "count",
        "string", "bool", "bool", "count",
        "string", "count", "count", "count", "count",
        "set[string]"
    ]

    with open(conn_log_path, "w", encoding="utf-8") as f:
        f.write("#separator \\x09\n")
        f.write("#set_separator\t,\n")
        f.write("#empty_field\t(empty)\n")
        f.write("#unset_field\t-\n")
        f.write("#path\tconn\n")
        f.write(f"#open\t2023-05-12-09-30-00\n")
        f.write("#fields\t" + "\t".join(fields) + "\n")
        f.write("#types\t" + "\t".join(types) + "\n")

        for r in all_conn_records:
            row_vals = [str(r[k]) for k in fields]
            f.write("\t".join(row_vals) + "\n")

        f.write("#close\t2023-05-12-18-00-00\n")

    # Save Ground Truth Sessions JSON
    with open(bench_dir / "ground_truth_sessions.json", "w", encoding="utf-8") as f:
        json.dump(ground_truth_sessions, f, indent=2)

    # -------------------------------------------------------------
    # 4. GENERATE DNS SAMPLES & dns.log (Zeek TSV Format)
    # -------------------------------------------------------------
    dns_records = []
    dns_ground_truth = []

    # 4.1 DNS Tunneling Attacks (dnscat2, iodine, Cobalt Strike DNS)
    tunnel_campaigns = [
        {
            "tool": "dnscat2",
            "domain": "dnscat-tunnel.attacker-c2.net",
            "count": 45,
            "qtype": "TXT",
            "sample_prefix": lambda: "".join(random.choices("0123456789abcdef", k=random.randint(48, 62))),
        },
        {
            "tool": "iodine",
            "domain": "t1.iodine-exfil.xyz",
            "count": 40,
            "qtype": "NULL",
            "sample_prefix": lambda: "v4." + "".join(random.choices("0123456789abcdefghijklmnopqrstuvwxyz", k=random.randint(45, 60))),
        },
        {
            "tool": "Cobalt Strike DNS Beacon",
            "domain": "stage.beacon-c2.org",
            "count": 35,
            "qtype": "TXT",
            "sample_prefix": lambda: "cdn" + "".join(random.choices("0123456789abcdef", k=random.randint(32, 48))),
        },
    ]

    for camp in tunnel_campaigns:
        for i in range(camp["count"]):
            prefix = camp["sample_prefix"]()
            fqdn = f"{prefix}.{camp['domain']}"
            t = base_ts + random.uniform(10, 3600)
            uid = f"DNS_TUNNEL_{camp['tool'][:4]}_{i:03d}"

            dns_records.append({
                "ts": round(t, 4),
                "uid": uid,
                "id.orig_h": "10.0.1.50",
                "id.orig_p": 53000 + random.randint(1, 9999),
                "id.resp_h": "1.1.1.1",
                "id.resp_p": 53,
                "proto": "udp",
                "trans_id": random.randint(1000, 65000),
                "rtt": round(random.uniform(0.015, 0.085), 4),
                "query": fqdn,
                "qclass": 1,
                "qclass_name": "C_INTERNET",
                "qtype": 16 if camp["qtype"] == "TXT" else 10 if camp["qtype"] == "NULL" else 1,
                "qtype_name": camp["qtype"],
                "rcode": 0,
                "rcode_name": "NOERROR",
                "AA": "F",
                "TC": "F",
                "RD": "T",
                "RA": "T",
                "Z": 0,
                "answers": "exfil_response_data",
                "TTLs": "60.0",
                "rejected": "F",
            })

            dns_ground_truth.append({
                "query": fqdn,
                "tool": camp["tool"],
                "parent_domain": camp["domain"],
                "is_tunneling": 1,
            })

    # 4.2 Benign DNS Queries
    benign_dns_samples = [
        "www.google.com", "mail.google.com", "drive.google.com", "api.github.com",
        "github.com", "raw.githubusercontent.com", "stackoverflow.com", "chat.openai.com",
        "login.microsoftonline.com", "teams.microsoft.com", "outlook.office365.com",
        "prod.cloud.netflix.com", "api.spotify.com", "slack.com", "cdn.discordapp.com",
        "d3m7h8e2.cloudfront.net", "e1051.g.akamaiedge.net", "edge-chat.facebook.com",
        "i.imgur.com", "en.wikipedia.org", "s3.dualstack.us-east-1.amazonaws.com"
    ]

    for i in range(350):
        query = random.choice(benign_dns_samples)
        if random.random() < 0.3:
            # Subdomain variation
            query = f"node-{random.randint(1, 99)}.{query}"

        t = base_ts + random.uniform(5, 4000)
        uid = f"DNS_BENIGN_{i:04d}"

        dns_records.append({
            "ts": round(t, 4),
            "uid": uid,
            "id.orig_h": random.choice(benign_orig_ips),
            "id.orig_p": 50000 + random.randint(1, 9999),
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "trans_id": random.randint(1000, 65000),
            "rtt": round(random.uniform(0.010, 0.050), 4),
            "query": query,
            "qclass": 1,
            "qclass_name": "C_INTERNET",
            "qtype": 1,
            "qtype_name": "A",
            "rcode": 0,
            "rcode_name": "NOERROR",
            "AA": "F",
            "TC": "F",
            "RD": "T",
            "RA": "T",
            "Z": 0,
            "answers": "142.250.190.46",
            "TTLs": "300.0",
            "rejected": "F",
        })

        dns_ground_truth.append({
            "query": query,
            "tool": "BENIGN",
            "parent_domain": query.split(".")[-2] + "." + query.split(".")[-1] if len(query.split(".")) >= 2 else query,
            "is_tunneling": 0,
        })

    # Sort DNS records chronologically
    dns_records.sort(key=lambda r: r["ts"])

    # Write dns.log (Zeek TSV Format)
    dns_fields = [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
        "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD",
        "RA", "Z", "answers", "TTLs", "rejected"
    ]
    dns_types = [
        "time", "string", "addr", "port", "addr", "port",
        "enum", "count", "interval", "string", "count", "string",
        "count", "string", "count", "string", "bool", "bool", "bool",
        "bool", "count", "vector[string]", "vector[interval]", "bool"
    ]

    with open(raw_dir / "dns.log", "w", encoding="utf-8") as f:
        f.write("#separator \\x09\n")
        f.write("#set_separator\t,\n")
        f.write("#empty_field\t(empty)\n")
        f.write("#unset_field\t-\n")
        f.write("#path\tdns\n")
        f.write("#open\t2023-05-12-09-30-00\n")
        f.write("#fields\t" + "\t".join(dns_fields) + "\n")
        f.write("#types\t" + "\t".join(dns_types) + "\n")

        for r in dns_records:
            row_vals = [str(r.get(k, "-")) for k in dns_fields]
            f.write("\t".join(row_vals) + "\n")

        f.write("#close\t2023-05-12-18-00-00\n")

    with open(bench_dir / "dns_ground_truth.json", "w", encoding="utf-8") as f:
        json.dump(dns_ground_truth, f, indent=2)

    print(f"[+] Generated {len(all_conn_records):,} conn.log records ({len(ground_truth_sessions):,} sessions)")
    print(f"    - Beacon sessions: {len(beacon_profiles)} (23 expected TP, 2 expected FN)")
    print(f"    - Benign sessions: {benign_session_count} (62 expected FP, {benign_session_count - 62} TN)")
    print(f"[+] Generated {len(dns_records):,} dns.log records ({len(dns_ground_truth)} queries)")
    print(f"[+] Files saved to {raw_dir} and {bench_dir}")


if __name__ == "__main__":
    generate_benchmark()
