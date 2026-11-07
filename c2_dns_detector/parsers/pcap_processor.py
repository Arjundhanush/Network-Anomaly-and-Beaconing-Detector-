"""
PCAP processing utility.
Enables processing PCAP files directly by invoking Zeek or extracting flow/DNS summaries.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple
import pandas as pd

from .zeek_conn import parse_conn_log
from .zeek_dns import parse_dns_log


class PcapProcessor:
    """Processes PCAP files through Zeek or native fallback to generate DataFrames."""

    def __init__(self, zeek_binary: Optional[str] = None):
        self.zeek_binary = zeek_binary or shutil.which("zeek") or shutil.which("bro")

    def is_zeek_available(self) -> bool:
        """Check if Zeek is installed and executable."""
        return self.zeek_binary is not None

    def process_pcap(self, pcap_path: Path, output_dir: Optional[Path] = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Process a PCAP file using Zeek to produce conn.log and dns.log DataFrames.
        
        Args:
            pcap_path: Path to the .pcap or .pcapng file.
            output_dir: Optional directory to store generated Zeek logs.

        Returns:
            Tuple of (conn_df, dns_df)
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        if not self.is_zeek_available():
            raise EnvironmentError(
                "Zeek binary not found in system PATH. Please install Zeek (https://zeek.org) "
                "or provide pre-parsed Zeek logs (conn.log and dns.log)."
            )

        work_dir = Path(output_dir) if output_dir else pcap_path.parent / f"zeek_{pcap_path.stem}"
        work_dir.mkdir(parents=True, exist_ok=True)

        cmd = [self.zeek_binary, "-r", str(pcap_path.resolve()), "LogAscii::use_json=F"]
        subprocess.run(cmd, cwd=str(work_dir), check=True, capture_output=True)

        conn_log = work_dir / "conn.log"
        dns_log = work_dir / "dns.log"

        conn_df = parse_conn_log(conn_log) if conn_log.exists() else pd.DataFrame()
        dns_df = parse_dns_log(dns_log) if dns_log.exists() else pd.DataFrame()

        return conn_df, dns_df
