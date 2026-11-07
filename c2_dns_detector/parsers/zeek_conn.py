"""
Zeek conn.log parser supporting TSV (standard Zeek ASCII format) and JSON-lines format.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Union
import pandas as pd


class ConnLogParser:
    """Parser for Zeek connection logs (conn.log)."""

    EXPECTED_FIELDS = [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "conn_state", "local_orig", "local_resp", "missed_bytes",
        "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
        "tunnel_parents"
    ]

    NUMERIC_FIELDS = {
        "ts": float,
        "id.orig_p": int,
        "id.resp_p": int,
        "duration": float,
        "orig_bytes": int,
        "resp_bytes": int,
        "missed_bytes": int,
        "orig_pkts": int,
        "orig_ip_bytes": int,
        "resp_pkts": int,
        "resp_ip_bytes": int,
    }

    def __init__(self, filepath: Optional[Union[str, Path]] = None):
        self.filepath = Path(filepath) if filepath else None

    def parse(self, filepath: Optional[Union[str, Path]] = None) -> pd.DataFrame:
        """Parse Zeek conn.log into a pandas DataFrame."""
        path = Path(filepath) if filepath else self.filepath
        if not path or not path.exists():
            raise FileNotFoundError(f"conn.log file not found: {path}")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline()

        if first_line.startswith("{"):
            return self._parse_json(path)
        else:
            return self._parse_tsv(path)

    def _parse_json(self, path: Path) -> pd.DataFrame:
        """Parse JSON-lines formatted Zeek log."""
        records = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    records.append(record)
                except json.JSONDecodeError:
                    continue

        df = pd.DataFrame(records)
        return self._normalize_dataframe(df)

    def _parse_tsv(self, path: Path) -> pd.DataFrame:
        """Parse ASCII TSV formatted Zeek log with #fields directive."""
        fields = []
        records = []
        separator = "\t"

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip("\r\n")
                if not line:
                    continue
                if line.startswith("#separator"):
                    # e.g., #separator \x09
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
        """Clean and typecast DataFrame columns."""
        if df.empty:
            return pd.DataFrame(columns=self.EXPECTED_FIELDS)

        # Standardize nested names if needed
        rename_map = {
            "id_orig_h": "id.orig_h",
            "id_orig_p": "id.orig_p",
            "id_resp_h": "id.resp_h",
            "id_resp_p": "id.resp_p",
        }
        df = df.rename(columns=rename_map)

        # Type conversion and handling unset '-' values
        for col, dtype in self.NUMERIC_FIELDS.items():
            if col in df.columns:
                df[col] = df[col].replace(["-", "(empty)", "None", ""], 0)
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(dtype)

        # Ensure ts is sorted
        if "ts" in df.columns:
            df = df.sort_values(by="ts").reset_index(drop=True)

        return df


def parse_conn_log(filepath: Union[str, Path]) -> pd.DataFrame:
    """Convenience function to parse a Zeek conn.log."""
    parser = ConnLogParser(filepath)
    return parser.parse()
