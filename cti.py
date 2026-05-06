"""
rbi/core/cti.py
Cyber Threat Intelligence (CTI) database checker.

Checks:
  - Domain blacklist
  - IP blacklist
  - Known safe domains (allowlist fast-path)
  - Risk score lookup
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from logger import get_logger

log = get_logger("cti")

_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "cti_db.json")


def _load_db() -> dict:
    with open(_DB_PATH, "r") as f:
        return json.load(f)


@dataclass
class CTIResult:
    passed: bool
    risk_score: int = 0
    reason: Optional[str] = None
    details: list[str] = field(default_factory=list)


def check(domain: str, ip: Optional[str] = None) -> CTIResult:
    """
    Run CTI checks against the given domain and optional resolved IP.
    Returns a CTIResult with pass/fail, risk score, and reason.
    """
    db = _load_db()
    details = []

    log.info(f"CTI check → domain={domain!r}  ip={ip!r}")

    # 1. Known safe allowlist (fast-path)
    if domain in db.get("known_safe_domains", []):
        score = db.get("risk_scores", {}).get(domain, 1)
        log.info(f"  [ALLOWLIST] {domain!r} is a known-safe domain  score={score}")
        details.append(f"Domain '{domain}' is on the known-safe allowlist")
        return CTIResult(passed=True, risk_score=score, details=details)

    # 2. Domain blacklist
    if domain in db.get("blacklisted_domains", []):
        score = db.get("risk_scores", {}).get(domain, 90)
        reason = f"Domain '{domain}' is on the CTI blacklist"
        log.warning(f"  [BLOCK] {reason}")
        details.append(reason)
        return CTIResult(passed=False, risk_score=score, reason=reason, details=details)

    # 3. IP blacklist
    if ip and ip in db.get("blacklisted_ips", []):
        reason = f"IP {ip} is on the CTI blacklist"
        log.warning(f"  [BLOCK] {reason}")
        details.append(reason)
        return CTIResult(passed=False, risk_score=95, reason=reason, details=details)

    # 4. Compute a heuristic risk score for unknown domains
    score = _heuristic_score(domain, db)
    log.info(f"  [PASS] domain={domain!r}  heuristic_score={score}")
    details.append(f"No blacklist match for domain '{domain}'")
    if ip:
        details.append(f"IP {ip} not in CTI blacklist")

    return CTIResult(passed=True, risk_score=score, details=details)


def check_phishing_patterns(text: str) -> tuple[bool, Optional[str]]:
    """
    Scan page text/HTML for phishing keywords defined in the CTI DB.
    Returns (is_phishing, matched_pattern).
    """
    db = _load_db()
    patterns = db.get("phishing_patterns", [])
    lowered = text.lower()
    for pat in patterns:
        if re.search(pat, lowered):
            log.warning(f"  [PHISHING] Pattern matched: {pat!r}")
            return True, pat
    return False, None


def _heuristic_score(domain: str, db: dict) -> int:
    """Simple heuristic: unknown TLDs, long domains, or numeric subdomains score higher."""
    score = 10
    suspicious_tlds = {".xyz", ".top", ".club", ".online", ".site", ".bad", ".evil", ".test"}
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 40
            break
    if len(domain) > 30:
        score += 15
    parts = domain.split(".")
    if any(p.isdigit() for p in parts):
        score += 10
    # Known popular TLDs are safer
    safe_tlds = {".com", ".org", ".net", ".edu", ".gov"}
    for tld in safe_tlds:
        if domain.endswith(tld):
            score = max(score - 5, 1)
            break
    return min(score, 100)
