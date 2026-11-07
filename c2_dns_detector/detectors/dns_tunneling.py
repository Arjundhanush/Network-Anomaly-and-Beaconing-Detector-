"""
DNS Tunneling Detector using Shannon entropy, query-length distributions, and structural lexical features.
Detects data exfiltration and C2 tunneling (e.g., dnscat2, iodine, Cobalt Strike DNS beacons).
"""

from collections import Counter
from dataclasses import asdict, dataclass
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np
import pandas as pd


@dataclass
class DnsTunnelResult:
    """DNS tunneling detection result for an individual query or aggregated domain."""
    query: str
    parent_domain: str
    subdomain: str
    query_length: int
    longest_label_length: int
    label_count: int
    shannon_entropy: float
    digit_ratio: float
    hex_ratio: float
    vowel_ratio: float
    qtype: str
    tunnel_score: float             # [0 - 100]
    is_tunneling: bool
    threat_confidence: str          # LOW, MEDIUM, HIGH, CRITICAL

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DnsTunnelDetector:
    """
    Detector for DNS data exfiltration and tunneling channels.
    Combines information entropy, RFC label length boundaries, and lexical character distributions.
    """

    KNOWN_TLDS: Set[str] = {
        "com", "org", "net", "edu", "gov", "mil", "io", "co", "uk", "de", "ru",
        "cn", "info", "biz", "me", "xyz", "top", "club", "site", "online", "cloud"
    }

    KNOWN_CDN_WHITELIST: Set[str] = {
        "akadns.net", "akamaized.net", "cloudflare.net", "cloudfront.net",
        "trafficmanager.net", "fastly.net", "azureedge.net", "google.com",
        "googleapis.com", "microsoft.com", "windowsupdate.com", "apple.com"
    }

    def __init__(
        self,
        entropy_threshold: float = 3.6,
        length_threshold: int = 35,
        longest_label_threshold: int = 24,
        tunnel_score_threshold: float = 65.0,
    ):
        """
        Args:
            entropy_threshold: Shannon entropy cutoff (bits/char) for high randomness.
            length_threshold: Total query length cutoff for anomalous queries.
            longest_label_threshold: Maximum label length cutoff (RFC 1035 max 63).
            tunnel_score_threshold: Composite score cutoff [0 - 100] to flag tunneling.
        """
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.longest_label_threshold = longest_label_threshold
        self.tunnel_score_threshold = tunnel_score_threshold

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """
        Compute Shannon information entropy in bits per character:
        H(X) = - sum( p(x) * log2(p(x)) )
        """
        if not text:
            return 0.0

        length = len(text)
        counts = Counter(text)
        entropy = 0.0

        for count in counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)

        return round(float(entropy), 4)

    def extract_domain_components(self, query: str) -> Tuple[str, str, List[str]]:
        """
        Split a FQDN query into parent domain, subdomain, and labels.
        e.g., 'a8f93e.payload.tunnel.example.com' -> ('example.com', 'a8f93e.payload.tunnel', [...])
        """
        cleaned = query.strip().rstrip(".").lower()
        if not cleaned:
            return "", "", []

        labels = cleaned.split(".")
        if len(labels) <= 1:
            return cleaned, "", labels

        # Simple ETLD+1 parser
        if len(labels) >= 2:
            if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "gov"} and labels[-1] in self.KNOWN_TLDS:
                parent = ".".join(labels[-3:])
                subdomain = ".".join(labels[:-3])
            else:
                parent = ".".join(labels[-2:])
                subdomain = ".".join(labels[:-2])
        else:
            parent = cleaned
            subdomain = ""

        return parent, subdomain, labels

    def extract_lexical_features(self, subdomain: str) -> Dict[str, float]:
        """Compute lexical ratios (digits, hex chars, vowels) for subdomain string."""
        if not subdomain:
            return {"digit_ratio": 0.0, "hex_ratio": 0.0, "vowel_ratio": 0.0}

        cleaned = subdomain.replace(".", "").replace("-", "").replace("_", "")
        if not cleaned:
            return {"digit_ratio": 0.0, "hex_ratio": 0.0, "vowel_ratio": 0.0}

        length = len(cleaned)
        digits = sum(c.isdigit() for c in cleaned)
        hex_chars = sum(c in "0123456789abcdefABCDEF" for c in cleaned)
        alphas = [c for c in cleaned if c.isalpha()]
        vowels = sum(c in "aeiouAEIOU" for c in alphas)

        digit_ratio = digits / length
        hex_ratio = hex_chars / length
        vowel_ratio = (vowels / len(alphas)) if alphas else 0.0

        return {
            "digit_ratio": round(digit_ratio, 4),
            "hex_ratio": round(hex_ratio, 4),
            "vowel_ratio": round(vowel_ratio, 4),
        }

    def score_query(
        self,
        query: str,
        qtype: str = "A"
    ) -> DnsTunnelResult:
        """Analyze a single DNS query and compute tunneling confidence score."""
        parent, subdomain, labels = self.extract_domain_components(query)

        query_len = len(query.strip().rstrip("."))
        longest_label = max((len(lbl) for lbl in labels), default=0)
        label_count = len(labels)

        # Primary label entropy (longest label carries the encoded chunk)
        longest_label_str = max(labels, key=len, default="")
        entropy = self.calculate_shannon_entropy(longest_label_str)

        lexical = self.extract_lexical_features(subdomain)

        # Base scoring components
        # 1. Entropy component (Max 35 pts)
        if entropy >= 4.2:
            s_entropy = 35.0
        elif entropy >= self.entropy_threshold:
            s_entropy = 20.0 + 15.0 * ((entropy - self.entropy_threshold) / (4.2 - self.entropy_threshold))
        elif entropy >= 3.0:
            s_entropy = 10.0 * ((entropy - 3.0) / (self.entropy_threshold - 3.0))
        else:
            s_entropy = 0.0

        # 2. Length component (Max 30 pts)
        if query_len >= 60:
            s_len = 30.0
        elif query_len >= self.length_threshold:
            s_len = 15.0 + 15.0 * ((query_len - self.length_threshold) / (60 - self.length_threshold))
        else:
            s_len = 0.0

        # 3. Longest label component (Max 20 pts)
        if longest_label >= 45:
            s_label = 20.0
        elif longest_label >= self.longest_label_threshold:
            s_label = 10.0 + 10.0 * ((longest_label - self.longest_label_threshold) / (45 - self.longest_label_threshold))
        else:
            s_label = 0.0

        # 4. Lexical encoding indicator (Max 15 pts)
        s_lex = 0.0
        # High hex ratio + low vowel ratio indicates hex/base32 payload
        if lexical["hex_ratio"] >= 0.85 and longest_label >= 16:
            s_lex += 10.0
        if lexical["vowel_ratio"] < 0.15 and len(subdomain) > 15:
            s_lex += 5.0

        # Record type bonus (e.g., TXT queries frequently used by dnscat2/iodine for data channel)
        qtype_upper = str(qtype).upper()
        if qtype_upper in {"TXT", "NULL", "16", "10"}:
            s_lex += 10.0

        # CDN Whitelist dampener
        is_known_cdn = any(parent.endswith(cdn) for cdn in self.KNOWN_CDN_WHITELIST)
        raw_score = s_entropy + s_len + s_label + s_lex

        if is_known_cdn:
            raw_score *= 0.45  # Reduce score for benign CDN hostnames

        final_score = float(np.clip(raw_score, 0.0, 100.0))
        is_tunneling = final_score >= self.tunnel_score_threshold

        if final_score >= 85.0:
            confidence = "CRITICAL"
        elif final_score >= 70.0:
            confidence = "HIGH"
        elif final_score >= 55.0:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return DnsTunnelResult(
            query=query,
            parent_domain=parent,
            subdomain=subdomain,
            query_length=query_len,
            longest_label_length=longest_label,
            label_count=label_count,
            shannon_entropy=entropy,
            digit_ratio=lexical["digit_ratio"],
            hex_ratio=lexical["hex_ratio"],
            vowel_ratio=lexical["vowel_ratio"],
            qtype=qtype_upper,
            tunnel_score=round(final_score, 2),
            is_tunneling=is_tunneling,
            threat_confidence=confidence,
        )

    def detect(self, dns_df: pd.DataFrame) -> List[DnsTunnelResult]:
        """
        Analyze all queries in a Zeek dns.log DataFrame.
        
        Args:
            dns_df: DataFrame parsed from Zeek dns.log.

        Returns:
            List of DnsTunnelResult objects.
        """
        if dns_df.empty or "query" not in dns_df.columns:
            return []

        results: List[DnsTunnelResult] = []
        qtype_col = "qtype_name" if "qtype_name" in dns_df.columns else "qtype"

        for _, row in dns_df.iterrows():
            query = str(row.get("query", ""))
            if not query or query in {"-", "(empty)"}:
                continue
            qtype = str(row.get(qtype_col, "A"))
            res = self.score_query(query=query, qtype=qtype)
            results.append(res)

        results.sort(key=lambda r: r.tunnel_score, reverse=True)
        return results

    def aggregate_by_domain(self, results: List[DnsTunnelResult]) -> pd.DataFrame:
        """Aggregate tunneling metrics by parent domain to detect sustained tunneling campaigns."""
        if not results:
            return pd.DataFrame()

        records = [r.to_dict() for r in results]
        df = pd.DataFrame(records)

        agg = df.groupby("parent_domain").agg(
            total_queries=("query", "count"),
            unique_subdomains=("subdomain", "nunique"),
            max_query_length=("query_length", "max"),
            max_entropy=("shannon_entropy", "max"),
            mean_entropy=("shannon_entropy", "mean"),
            mean_tunnel_score=("tunnel_score", "mean"),
            max_tunnel_score=("tunnel_score", "max"),
            flagged_tunnel_queries=("is_tunneling", "sum"),
        ).reset_index()

        agg["is_tunnel_domain"] = (agg["max_tunnel_score"] >= self.tunnel_score_threshold) & (agg["unique_subdomains"] >= 2)
        agg = agg.sort_values(by="max_tunnel_score", ascending=False).reset_index(drop=True)
        return agg

    def to_dataframe(self, results: List[DnsTunnelResult]) -> pd.DataFrame:
        """Convert list of DnsTunnelResult to pandas DataFrame."""
        if not results:
            return pd.DataFrame()
        return pd.DataFrame([r.to_dict() for r in results])
