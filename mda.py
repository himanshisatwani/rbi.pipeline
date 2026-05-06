"""
rbi/core/mda.py
Message Digest Analysis (MDA).

Checks:
  - SMA-256  : structural message authentication (SHA-256 HMAC of content)
  - SMD-512  : structural message digest (SHA-512 of content)
  - Phishing pattern scan on extracted text
  - IP reputation heuristic
"""

import hashlib
import hmac
import re
import socket
from dataclasses import dataclass, field
from typing import Optional

from logger import get_logger

log = get_logger("mda")

# Shared secret used for SMA-256 HMAC signing.
# In production this would be a rotated key from a secrets manager.
_HMAC_SECRET = b"rbi-proxy-isolation-key-2024"


@dataclass
class MDAResult:
    passed: bool
    sma256: str = ""
    smd512: str = ""
    phishing_detected: bool = False
    ip_reputation: str = "unknown"
    reason: Optional[str] = None
    details: list[str] = field(default_factory=list)


def check(content: bytes, text: str, domain: str, ip: Optional[str] = None) -> MDAResult:
    """
    Full MDA sweep:
      1. Compute SMA-256 (HMAC-SHA256) and SMD-512 (SHA-512)
      2. Scan text for phishing patterns
      3. Evaluate IP reputation
    """
    details = []

    # --- SMA-256 (HMAC-SHA256) ---
    sma256 = hmac.new(_HMAC_SECRET, content, hashlib.sha256).hexdigest()
    log.info(f"  SMA-256: {sma256[:24]}…")
    details.append(f"SMA-256 : {sma256}")

    # --- SMD-512 (SHA-512) ---
    smd512 = hashlib.sha512(content).hexdigest()
    log.info(f"  SMD-512: {smd512[:24]}…")
    details.append(f"SMD-512 : {smd512}")

    # --- Phishing pattern scan ---
    phishing, matched_pattern = _phishing_scan(text)
    if phishing:
        reason = f"Phishing pattern detected: '{matched_pattern}'"
        log.warning(f"  [BLOCK] {reason}")
        details.append(f"PHISHING: {reason}")
        return MDAResult(
            passed=False,
            sma256=sma256,
            smd512=smd512,
            phishing_detected=True,
            reason=reason,
            details=details,
        )
    details.append("Phishing scan: no patterns matched")

    # --- IP reputation ---
    ip_rep = _ip_reputation(ip or domain)
    details.append(f"IP reputation: {ip_rep}")
    log.info(f"  IP reputation: {ip_rep}")

    if ip_rep == "SUSPICIOUS":
        reason = f"IP {ip} flagged as suspicious by reputation heuristic"
        log.warning(f"  [WARN] {reason}")
        # Warn but don't hard-block on heuristic alone
        details.append(f"WARNING: {reason}")

    log.info("  [PASS] MDA checks complete")
    return MDAResult(
        passed=True,
        sma256=sma256,
        smd512=smd512,
        phishing_detected=False,
        ip_reputation=ip_rep,
        details=details,
    )


# ── Phishing scan ─────────────────────────────────────────────────────────────

_PHISHING_PATTERNS = [
    r"login.*paypal",
    r"signin.*amazon",
    r"verify.*bank",
    r"account.*suspended",
    r"update.*password.*now",
    r"click.*here.*claim",
    r"you.*won.*prize",
    r"enter.*credit.*card",
    r"confirm.*identity",
    r"unusual.*activity.*account",
]


def _phishing_scan(text: str) -> tuple[bool, Optional[str]]:
    lowered = text.lower()
    for pat in _PHISHING_PATTERNS:
        if re.search(pat, lowered):
            return True, pat
    return False, None


# ── IP reputation ──────────────────────────────────────────────────────────────

_SUSPICIOUS_RANGES = [
    # Well-known Tor exit / abuse ranges (illustrative)
    "185.220.",
    "199.87.",
    "192.42.",
    "198.96.",
]


def _ip_reputation(ip_or_domain: str) -> str:
    if not ip_or_domain:
        return "unknown"
    for prefix in _SUSPICIOUS_RANGES:
        if ip_or_domain.startswith(prefix):
            return "SUSPICIOUS"
    # Private / loopback → internal (safe in this context)
    if ip_or_domain.startswith(("10.", "192.168.", "127.", "::1")):
        return "INTERNAL"
    return "CLEAN"
