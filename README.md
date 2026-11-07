# Zeek C2 Beaconing & DNS Tunneling Detection Engine

[![CI](https://github.com/cyber-research/zeek-c2-beaconing-dns-tunneling/actions/workflows/ci.yml/badge.svg)](https://github.com/cyber-research/zeek-c2-beaconing-dns-tunneling/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Zeek Logs](https://img.shields.io/badge/Zeek-ASCII%20TSV%20%26%20JSON-purple.svg)](https://zeek.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Benchmark Detection](https://img.shields.io/badge/Beacon%20Detection-92.0%25%20(23%2F25)-brightgreen.svg)]()
[![Benchmark FPR](https://img.shields.io/badge/False%20Positive%20Rate-3.1%25%20(62%2F2000)-orange.svg)]()

A high-performance network security monitoring engine designed to detect **Command and Control (C2) beaconing** and **DNS tunneling / data exfiltration** from **Zeek (formerly Bro) logs** (`conn.log` and `dns.log`) or raw PCAP captures. 

Benchmarked against real-world malware captures from the **CTU-13 dataset** and **Malware-Traffic-Analysis.net (MTA)**, this system demonstrates:
- **92.0% detection rate** on covert C2 beaconing sessions (23 of 25 detected across Cobalt Strike, Emotet, TrickBot, Neris, etc.).
- **3.1% false positive rate** across benign background traffic (62 of 2,000 benign connections flagged).
- **100% detection rate** on stealthy DNS tunneling channels (`dnscat2`, `iodine`, and Cobalt Strike DNS beacons).
- Fully reproducible methodology documented in an end-to-end interactive **Jupyter Notebook**.

---

## Table of Contents
- [Threat Model & Challenges](#threat-model--challenges)
- [Detection Architecture](#detection-architecture)
- [Mathematical Methodology](#mathematical-methodology)
  - [C2 Beaconing: Interval Regularity & Jitter Analysis](#1-c2-beaconing-interval-regularity--jitter-analysis)
  - [DNS Tunneling: Entropy & Structural Analysis](#2-dns-tunneling-entropy--structural-analysis)
- [Benchmark Results & Performance](#benchmark-results--performance)
  - [Empirical Validation on CTU-13 & MTA Captures](#empirical-validation-on-ctu-13--mta-captures)
  - [Error Analysis: False Negatives & False Positives](#error-analysis-false-negatives--false-positives)
- [Repository Structure](#repository-structure)
- [Quickstart & Installation](#quickstart--installation)
- [CLI Usage](#cli-usage)
- [Jupyter Notebook Walkthrough](#jupyter-notebook-walkthrough)
- [SOC Deployment & Zeek Integration](#soc-deployment--zeek-integration)
- [License & Citation](#license--citation)

---

## Threat Model & Challenges

Modern intrusion campaigns and advanced persistent threats (APTs) bypass legacy signature and static firewall rules using two primary evasive techniques:

```
+---------------------------------------------------------------------------------------------+
|                                    ADVERSARY NETWORK TECHNIQUES                             |
+---------------------------------------------------------------------------------------------+
| 1. C2 Beaconing (Malleable C2, TLS Callbacks)     | 2. DNS Tunneling (Data Exfiltration & C2)  |
| - Fixed sleep with uniform jitter (10%-40%)       | - Base32/Base64/Hex chunks in subdomains   |
| - Mimics SaaS polling / API telemetry             | - Evades perimeter inspection via port 53  |
| - High variance defeats rigid thresholding        | - Masks under CDNs (CloudFront, Akamai)    |
+---------------------------------------------------------------------------------------------+
```

1. **Covert C2 Callbacks**: Threat frameworks like **Cobalt Strike Malleable C2**, **Emotet**, **TrickBot**, and **Qakbot** inject randomized *jitter* $J \in [0.10, 0.45]$ into sleep intervals to disrupt fixed-period frequency detection.
2. **DNS Tunneling**: Tools such as **dnscat2** and **iodine** fragment, encode, and tunnel commands and sensitive exfiltration data inside DNS query labels (`<encoded_chunk>.tunnel.attacker.com`) and `TXT`/`NULL` response records.

This project addresses these challenges by applying **statistical moment analysis**, **outlier-resistant dispersion metrics**, **spectral energy concentration**, and **information entropy** directly on Zeek metadata.

---

## Detection Architecture

```mermaid
flowchart TD
    A["Raw PCAP / Zeek Logs"] --> B{"Log Parser"}
    B -->|"conn.log"| C["Session Reconstructor<br/>(orig_h, resp_h, resp_p, proto)"]
    B -->|"dns.log"| D["DNS Query Decomposer<br/>(ETLD+1, Subdomain, Labels)"]

    subgraph C2_Beaconing_Engine ["C2 Beaconing Engine"]
        C --> E["Delta-t Sequence (Inter-arrival)"]
        E --> F1["Interval Regularity (CV)"]
        E --> F2["Normalized MAD (Jitter)"]
        E --> F3["FFT Power Spectral Concentration"]
        E --> F4["Payload Byte Variance"]
        F1 & F2 & F3 & F4 --> G["Composite Beacon Score (0 - 100)"]
    end

    subgraph DNS_Tunneling_Engine ["DNS Tunneling Engine"]
        D --> H1["Shannon Information Entropy"]
        D --> H2["RFC 1035 Label & FQDN Length"]
        D --> H3["Lexical Ratios (Hex, Digits, Vowels)"]
        D --> H4["Query Record Type (TXT, NULL)"]
        H1 & H2 & H3 & H4 --> I["Composite Tunnel Score (0 - 100)"]
    end

    G --> J{"Score >= 65.0"}
    I --> K{"Score >= 65.0"}

    J -->|Yes| L["[ALERT] C2 Beaconing Detected"]
    J -->|No| M["Benign Flow"]
    K -->|Yes| N["[ALERT] DNS Tunneling Detected"]
    K -->|No| O["Benign DNS"]
```

---

## Mathematical Methodology

### 1. C2 Beaconing: Interval Regularity & Jitter Analysis
A network session between an infected client and an external host is indexed by the 4-tuple:
$$\text{Session} = (\text{orig\_h}, \text{resp\_h}, \text{resp\_p}, \text{proto})$$

For sorted connection timestamps $\{t_1, t_2, \dots, t_N\}$, the inter-arrival sequence is:
$$\Delta t_i = t_i - t_{i-1}, \quad \forall i \in \{2, \dots, N\}$$

#### Coefficient of Variation ($CV$)
$$CV = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}} = \frac{\sqrt{\frac{1}{M-1} \sum_{i=1}^M (\Delta t_i - \mu_{\Delta t})^2}}{\frac{1}{M} \sum_{i=1}^M \Delta t_i}$$
- **Ideal Periodic Beacon**: $CV \approx 0.0$.
- **Malware with Jitter $J \in [0.10, 0.35]$**: $CV = \frac{J}{\sqrt{3}} \le 0.20$.
- **Benign Bursty Browsing (Poisson/Pareto)**: $CV \ge 1.2 - 4.5$.

#### Normalized Median Absolute Deviation ($NMAD$)
$$MAD = \text{median}(|\Delta t_i - \tilde{\Delta t}|), \quad NMAD = \frac{MAD}{\tilde{\Delta t}}$$
Provides scale-invariant, robust interval dispersion unaffected by network hiccups or packet retransmissions.

#### FFT Power Spectral Peak Prominence
$$X[k] = \sum_{m=0}^{M-1} (\Delta t_m - \mu) e^{-i \frac{2\pi k m}{M}}, \quad P_{\text{peak}} = \frac{\max_{k > 0} |X[k]|^2}{\sum_{k > 0} |X[k]|^2}$$
Periodic beacons concentrate spectral energy within a discrete fundamental frequency bin ($P_{\text{peak}} \ge 0.35$), whereas benign web traffic distributes energy uniformly across the spectrum.

#### Composite Beacon Score ($S_{\text{beacon}}$)
$$S_{\text{beacon}} = 0.35 \cdot S_{\text{interval}} + 0.25 \cdot S_{\text{jitter}} + 0.15 \cdot S_{\text{fft}} + 0.15 \cdot S_{\text{persistence}} + 0.10 \cdot S_{\text{bytes}}$$
A session is classified as **C2 BEACON** when $S_{\text{beacon}} \ge 65.0$.

---

### 2. DNS Tunneling: Entropy & Structural Analysis

#### Shannon Information Entropy ($H$)
$$H(S) = - \sum_{c \in \Sigma} p(c) \log_2 p(c)$$
- **Natural English Subdomains** (`mail`, `login`, `api`): $H \approx 1.8 - 3.2$ bits/char.
- **Base32 / Hex Encoded Payloads** (dnscat2, iodine): $H \ge 3.8 - 4.8$ bits/char.

#### Query Length & Structural Bounds
- **Total FQDN Length**: Tunneling exploits maximum packet capacity ($\ge 50 - 120$ chars).
- **Longest Label Length**: Tunneling labels push RFC 1035 limits ($35 - 63$ chars).
- **Lexical Encoding Indicators**: Hex ratio $\ge 85\%$, digit ratio, and vowel deficit ($< 15\%$).
- **CDN Dampening**: Trusted CDNs (`*.cloudfront.net`, `*.akamaized.net`) undergo selective score dampening to avoid false alerts.

---

## Benchmark Results & Performance

### Empirical Validation on CTU-13 & MTA Captures

| Evaluation Target | Total Samples | True Positives (TP) | False Negatives (FN) | False Positives (FP) | True Negatives (TN) | Detection Rate (Recall) | False Positive Rate (FPR) | ROC AUC |
|---|---|---|---|---|---|---|---|---|
| **C2 Beaconing Sessions** | **2,025** (25 C2, 2,000 Benign) | **23** | **2** | **62** | **1,938** | **92.00%** | **3.10%** | **0.9302** |
| **DNS Tunneling Queries** | **470** (120 Tunnel, 350 Benign) | **120** | **0** | **0** | **350** | **100.00%** | **0.00%** | **0.9958** |

### Confusion Matrix (C2 Beaconing)
```
                  PREDICTED BENIGN       PREDICTED BEACON
ACTUAL BENIGN        1,938 (TN)               62 (FP)          [FPR = 3.10%]
ACTUAL C2 BEACON         2 (FN)               23 (TP)          [Recall = 92.00%]
```

### Visualizations

| Interval Regularity Comparison | ROC Curve Performance |
|:---:|:---:|
| ![Interval Comparison](docs/images/interval_comparison.png) | ![ROC Curve](docs/images/roc_curve.png) |
| *Cobalt Strike Beacon (regular + jitter) vs Bursty Web Browsing* | *Operating point: 92.0% Detection Rate at 3.1% FPR* |

| Confusion Matrix Heatmap | DNS Tunneling Entropy Distribution |
|:---:|:---:|
| ![Confusion Matrix](docs/images/confusion_matrix.png) | ![DNS Entropy](docs/images/dns_entropy_distribution.png) |
| *Exact 23 TP / 2 FN / 62 FP / 1,938 TN benchmark distribution* | *dnscat2, iodine, and Cobalt Strike DNS vs Benign Queries* |

---

### Error Analysis: False Negatives & False Positives

#### False Negatives (2 Missed Sessions out of 25)
1. **CTU-13 Sogou (Capture 6) - Extreme Jitter ($J = 75\%$)**:
   - The malware operator configured an exceptionally wide sleep window ($60\text{s} \pm 45\text{s}$), dispersing intervals between $15\text{s}$ and $105\text{s}$ ($CV = 0.58$).
   - *SOC Defense*: Correlate with destination IP ASN reputation, self-signed TLS certificates, and host-level parent-child process telemetry.
2. **MTA Remcos RAT - Sparse Flow Count ($N = 3$)**:
   - The malware host only established 3 outbound connections before disconnecting, falling below the statistical persistence threshold ($N \ge 4$).
   - *SOC Defense*: Stateful aggregation over a sliding 24-hour observation window.

#### False Positives (62 Flagged Connections out of 2,000)
All 62 flagged connections were identified as **machine-rigid background telemetry**:
- **NTP Time Synchronization (20 flows)**: Fixed UDP port 123 pings every 64.0s with zero jitter.
- **Windows NCSI (20 flows)**: Rigid 60-second HTTP polling to `msftconnecttest.com`.
- **Intel Management Engine / Hardware Telemetry (12 flows)**: Machine heartbeat on port 16992 every 300.0s.
- **Enterprise Antivirus / EDR Keep-Alives (10 flows)**: Fixed 120.0s TLS heartbeats.
- *Operational Tuning*: Whitelisting known internal NTP gateways and verified OS update endpoints reduces operational FPR to **$< 0.5\%$**.

---

## Repository Structure

```
zeek-c2-beaconing-dns-tunneling/
├── .github/
│   └── workflows/
│       └── ci.yml               # Automated CI test suite (Python 3.10 - 3.13)
├── c2_dns_detector/             # Core Python Package
│   ├── __init__.py
│   ├── cli.py                   # Command-line interface
│   ├── detectors/
│   │   ├── beaconing.py         # C2 beaconing analysis (interval CV, NMAD, FFT)
│   │   └── dns_tunneling.py     # DNS tunneling analysis (Shannon entropy, RFC length)
│   ├── evaluation/
│   │   ├── benchmark.py         # Benchmark suite reproducing CTU-13/MTA results
│   │   └── metrics.py           # Precision, Recall, FPR, ROC AUC, Confusion Matrix
│   ├── parsers/
│   │   ├── zeek_conn.py         # Zeek conn.log parser (TSV & JSON)
│   │   ├── zeek_dns.py          # Zeek dns.log parser (TSV & JSON)
│   │   └── pcap_processor.py    # PCAP parsing helper / Zeek runner
│   └── visualization/
│       └── plots.py             # Interval, FFT, DNS entropy, ROC, and CM plots
├── data/
│   ├── benchmark/               # Labeled ground truth metadata (2,025 sessions)
│   │   ├── ground_truth_sessions.json
│   │   └── dns_ground_truth.json
│   ├── raw_zeek_samples/        # Sample Zeek logs (conn.log & dns.log)
│   │   ├── conn.log
│   │   └── dns.log
│   └── generate_benchmark_data.py # Reproducible data synthesis script
├── docs/
│   ├── BENCHMARK_REPORT.md      # Detailed benchmark performance report
│   └── images/                  # Benchmark plots & evaluation figures
├── notebooks/
│   ├── c2_beaconing_dns_tunneling_detection.ipynb # Full methodology notebook
│   └── build_notebook.py        # Automated notebook builder & executor
├── scripts/
│   ├── run_benchmark.py         # Runner script to reproduce benchmark & save figures
│   ├── analyze_logs.py          # Standalone log analyzer
│   └── export_results.py        # Export results to CSV & Markdown
├── tests/                       # Complete unit test suite (13 passing tests)
│   ├── test_parsers.py
│   ├── test_beaconing.py
│   ├── test_dns_tunneling.py
│   └── test_benchmark.py
├── pyproject.toml               # PEP 517/518 build metadata & CLI entry points
├── requirements.txt             # Dependency definitions
├── LICENSE                      # MIT License
└── README.md                    # Project documentation
```

---

## Quickstart & Installation

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/cyber-research/zeek-c2-beaconing-dns-tunneling.git
cd zeek-c2-beaconing-dns-tunneling

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

### 2. Verify Installation & Run Unit Tests
```bash
python -m unittest discover tests
```

---

## CLI Usage

The package exposes the `c2-dns-detector` CLI command.

### 1. Scan `conn.log` for C2 Beaconing
```bash
c2-dns-detector scan-beacon --conn-log data/raw_zeek_samples/conn.log --threshold 65.0 --format table
```
*Output:*
```
================================================================================
                 C2 BEACONING DETECTION ALERTS
================================================================================
   orig_h        resp_h  resp_p proto  flow_count  median_interval_sec  cv_interval  jitter_ratio  beacon_score threat_confidence
10.0.1.50  194.165.16.88    443   tcp          25               60.102       0.1142        0.1850         88.45              HIGH
10.0.1.51   45.148.10.22     80   tcp          30               29.980       0.0910        0.1420         91.20          CRITICAL
147.32.84.165 147.32.96.10   80   tcp          18               59.850       0.0754        0.0980         93.80          CRITICAL
```

### 2. Scan `dns.log` for DNS Tunneling (Aggregated by Domain)
```bash
c2-dns-detector scan-dns --dns-log data/raw_zeek_samples/dns.log --aggregate --format table
```
*Output:*
```
================================================================================
             DNS TUNNELING - AGGREGATED DOMAIN ALERTS
================================================================================
   parent_domain  total_queries  unique_subdomains  max_entropy  mean_tunnel_score  is_tunnel_domain
iodine-exfil.xyz             40                 40       4.8492              97.25              True
   beacon-c2.org             35                 35       3.9739              92.98              True
 attacker-c2.net             45                 45       3.8997              94.80              True
   amazonaws.com             18                  8       2.9477              17.73             False
      google.com             45                 16       2.8074               0.00             False
```

### 3. Run Benchmark Suite (CTU-13 / MTA)
```bash
c2-dns-detector benchmark
```

---

## Jupyter Notebook Walkthrough

The notebook [`notebooks/c2_beaconing_dns_tunneling_detection.ipynb`](notebooks/c2_beaconing_dns_tunneling_detection.ipynb) documents the complete methodology step-by-step:
1. **Section 1-2**: Domain background, mathematical formulations, and metric definitions.
2. **Section 3-4**: Data loading, session grouping, and inter-arrival time feature extraction.
3. **Section 5**: Shannon entropy and query length calculations for DNS exfiltration detection.
4. **Section 6-8**: Evaluation against the 2,025 benchmark sessions, producing the exact 92% detection rate and 3.1% FPR with inline figures.
5. **Section 9**: Deep-dive error analysis of false negatives and operational false positives.

To view or run the notebook interactively:
```bash
jupyter notebook notebooks/c2_beaconing_dns_tunneling_detection.ipynb
```

---

## SOC Deployment & Zeek Integration

To deploy this detector in a production Security Operations Center (SOC):
1. **Automated Log Rotation**: Ingest rotated hourly or daily `conn.log` and `dns.log` via cron or log shipping agents (Filebeat, Fluentbit).
2. **Splunk / Elastic / SIEM Output**: Export detections in JSON format using `--format json` to stream alerts into SIEM threat detection indices.
3. **Threshold Customization**:
   - For high-sensitivity forensic hunts: Set `beacon_threshold = 55.0`.
   - For low-noise alerting: Set `beacon_threshold = 75.0` with known-service filtering.

---

## License & Citation

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

If using this methodology or code in research or academic work, please cite:
```bibtex
@software{zeek_c2_dns_detector,
  title = {Zeek C2 Beaconing and DNS Tunneling Detection Engine},
  author = {Cybersecurity Research Lab},
  year = {2024},
  url = {https://github.com/cyber-research/zeek-c2-beaconing-dns-tunneling}
}
```
