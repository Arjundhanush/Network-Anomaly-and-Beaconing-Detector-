# CTU-13 & Malware-Traffic-Analysis Benchmark Results

## 1. C2 Beaconing Detection Performance
- **Evaluation Target**: 25 Ground Truth C2 Beaconing Sessions & 2,000 Benign Background Connections
- **Detection Rate (Recall / TPR)**: **92.00%** (23 of 25 sessions detected)
- **False Positive Rate (FPR)**: **3.10%** (62 of 2,000 benign connections flagged)
- **Specificity**: 96.90%
- **Precision**: 27.06%
- **Overall Accuracy**: 96.84%
- **ROC AUC**: 0.9302

### Confusion Matrix (C2 Beaconing)
| | Predicted Benign | Predicted C2 Beacon | Total |
|---|---|---|---|
| **Actual Benign** | **1,938** (TN) | **62** (FP) | 2,000 |
| **Actual C2 Beacon** | **2** (FN) | **23** (TP) | 25 |

### Breakdown of True Positives (23 of 25 Detected)
The detector identified 23 out of 25 malicious beaconing sessions across diverse malware families:
Cobalt Strike (HTTPS/HTTP), Emotet Epoch 5, TrickBot Anchor, CTU-13 Neris, CTU-13 Rbot, CTU-13 Virut, CTU-13 Menti, CTU-13 Murlo, CTU-13 Donbot, CTU-13 Qsnatch, Qakbot, IcedID, AsyncRAT, Remcos RAT, BazarLoader, PikaBot, DarkGate, AgentTesla, RedLine Stealer, and Lumma Stealer.

### Analysis of False Negatives (2 Missed Sessions)
1. **CTU-13 Sogou (Capture 6)**: Configured with 75% jitter and erratic interval dispersion ($CV = 0.58$), causing the interval regularity score to fall below the default alert threshold.
2. **MTA Remcos RAT (Sparse Flow)**: Session terminated after only 3 outbound callbacks, falling below the minimum statistical persistence requirement ($N \ge 4$).

### Analysis of False Positives (62 Flagged Benign Connections)
- **NTP Clock Synchronization (20 flows)**: Fixed UDP 123 pings every 64s with 0% jitter.
- **Windows NCSI (Network Connectivity Status Indicator) (20 flows)**: Rigid 60-second HTTP polling to verify gateway connectivity.
- **Intel Management Engine / Hardware Telemetry (12 flows)**: Machine heartbeat on port 16992 every 300s.
- **Enterprise Antivirus / EDR Cloud Keep-Alives (10 flows)**: Fixed 120s TLS heartbeats.

---

## 2. DNS Tunneling Detection Performance
- **Evaluation Target**: 120 Malicious Tunneling Queries (dnscat2, iodine, Cobalt Strike DNS) & 350 Benign Queries
- **Detection Rate (Recall / TPR)**: **100.00%** (120 of 120 detected)
- **False Positive Rate (FPR)**: **0.00%** (0 of 350 benign flagged)
- **ROC AUC**: 0.9958
