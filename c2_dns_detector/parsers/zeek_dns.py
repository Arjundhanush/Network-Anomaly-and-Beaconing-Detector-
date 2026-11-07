"""
Zeek dns.log parser supporting TSV and JSON-lines format.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Union
import pandas as pd


class DnsLogParser:
    """Parser for Zeek DNS logs (dns.log)."""

    EXPECTED_FIELDS = [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
        "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD",
        "RA", "Z", "answers", "TTLs", "rejected"
    ]

    NUMERIC_FIELDS = {
        "ts": float,
        "id.orig_p": int,
        "id.resp_p": int,
        "trans_id": int,
        "rtt": float,
        "qclass": int,
        "qtype": int,
        "rcode": int,
    }

    def __init__(self, filepath: Optional[Union[str, Path]] = None):
        self.filepath = Path(filepath) if filepath else None

    def parse(self, filepath: Optional[Union[str, Path]] = None) -> pd.DataFrame:
        """Parse Zeek dns.log into a pandas DataFrame."""
        path = Path(filepath) if filepath else self.filepath
        if not path or not path.exists():
            raise FileNotFoundError(f"dns.log file not found: {path}")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline()

        if first_line.startswith("{"):
            return self._parse_json(path)
        else:
            return self._parse_tsv(path)

    def _parse_json(self, path: Path) -> pd.DataFrame:
        """Parse JSON-lines formatted Zeek dns.log."""
        records = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        df = pd.DataFrame(records)
        return self._normalize_dataframe(df)

    def _parse_tsv(self, path: Path) -> pd.DataFrame:
        """Parse ASCII TSV formatted Zeek dns.log."""
        fields = []
        records = []
        separator = "\t"

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip("\r\n")
                if not line:
                    continue
                if line.startswith("#separator"):
                    parts = line.split(maxsplit=1)
                    if len(parts) > 1:
                        sep_spec = parts[1]
                        if sep_spec == "\\x09":
                            separator = "\t"
                        elif sep_spec.startswith("\\x"):
                            separator = chr(int(sep_spec[2:], 16))
                        else:
                            separator = sep_spec
                    continue
                if line.startswith("#fields"):
                    fields = line.split(separator)[1:]
                    continue
                if line.startswith("#"):
                    continue

                if not fields:
                    continue

                parts = line.split(separator)
                if len(parts) == len(fields):
                    records.append(dict(zip(fields, parts)))

        df = pd.DataFrame(records)
        return self._normalize_dataframe(df)

    def _normalize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and normalize columns."""
        if df.empty:
            return pd.DataFrame(columns=self.EXPECTED_FIELDS)

        rename_map = {
            "id_orig_h": "id.orig_h",
            "id_orig_p": "id.orig_p",
            "id_resp_h": "id.resp_h",
            "id_resp_p": "id.resp_p",
        }
        df = df.rename(columns=rename_map)

        for col, dtype in self.NUMERIC_FIELDS.items():
            if col in df.columns:
                df[col] = df[col].replace(["-", "(empty)", "None", ""], 0)
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(dtype)

        if "query" in df.columns:
            df["query"] = df["query"].astype(str).str.strip().str.lower()
            # replace '-' with empty string
            df["query"] = df["query"].replace({"-": "", "(empty)": ""})

        if "ts" in df.columns:
            df = df.sort_values(by="ts").reset_index(drop=True)

        return df


def parse_dns_log(filepath: Union[str, Path]) -> pd.DataFrame:
    """Convenience function to parse a Zeek dns.log."""
    parser = DnsLogParser(filepath)
    return parser.parse()
