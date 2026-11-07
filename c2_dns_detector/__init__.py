"""
c2_dns_detector: Network Threat Detection Engine for Zeek Logs.

Detects Command and Control (C2) beaconing via interval regularity and jitter analysis,
and DNS tunneling via Shannon entropy and query-length structural features.
"""

__version__ = "1.0.0"
__author__ = "Cybersecurity Research Lab"

from .parsers.zeek_conn import parse_conn_log, ConnLogParser
from .parsers.zeek_dns import parse_dns_log, DnsLogParser
from .detectors.beaconing import C2BeaconDetector, BeaconResult, SessionFeatureExtractor
from .detectors.dns_tunneling import DnsTunnelDetector, DnsTunnelResult

__all__ = [
    "parse_conn_log",
    "ConnLogParser",
    "parse_dns_log",
    "DnsLogParser",
    "C2BeaconDetector",
    "BeaconResult",
    "SessionFeatureExtractor",
    "DnsTunnelDetector",
    "DnsTunnelResult",
]
