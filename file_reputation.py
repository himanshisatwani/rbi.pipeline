"""
rbi/core/file_reputation.py
File Reputation checker.

Computes MD5 and SHA-256 digests of the fetched content and checks
them against the known-malicious hash list in the CTI DB.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Optional

from logger import get_logger

log = get_logger("file_rep")

_DB_PATH = "data/cti_db.json"

@dataclass
class FileRepResult:
    passed: bool
    md5: str = ""
    sha256: str = ""
    reason: Optional[str] = None
    details: list[str] = field(default_factory=list)


def check(content: bytes) -> FileRepResult:
    """
    Hash the raw fetched content and check against known-malicious hashes.
    Returns FileRepResult with digest values and pass/fail.
    """
    with open(_DB_PATH) as f:
        db = json.load(f)

    malicious_hashes = set(db.get("malicious_sha256", []))

    md5_hex  = hashlib.md5(content).hexdigest()
    sha256_hex = hashlib.sha256(content).hexdigest()

    log.info(f"File reputation: md5={md5_hex[:16]}…  sha256={sha256_hex[:16]}…")

    details = [
        f"MD5    : {md5_hex}",
        f"SHA-256: {sha256_hex}",
    ]

    if sha256_hex in malicious_hashes:
        reason = f"SHA-256 {sha256_hex[:32]}… matches known-malicious hash"
        log.warning(f"  [BLOCK] {reason}")
        details.append(f"MATCH in malicious hash database")
        return FileRepResult(
            passed=False,
            md5=md5_hex,
            sha256=sha256_hex,
            reason=reason,
            details=details,
        )

    log.info("  [PASS] No hash match in malicious database")
    details.append("No match in malicious hash database")
    return FileRepResult(passed=True, md5=md5_hex, sha256=sha256_hex, details=details)
