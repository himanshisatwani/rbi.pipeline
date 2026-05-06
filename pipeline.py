"""
rbi/core/pipeline.py
RBI Security Pipeline Orchestrator.

Executes the full 3-layer + security-check flow:

  Layer 1  │  Client request → Proxy (MiM intercept)
  Layer 2  │  Proxy fetches content from remote site
  Layer 3  │  Security inspection:
           │    ├─ CTI Database check (domain + IP)
           │    ├─ File Reputation (MD5 + SHA-256)
           │    └─ MDA Analysis (SMA-256, SMD-512, phishing, IP rep)
           │
           └─ If all pass → Sanitise HTML → Return clean text

Each stage emits structured log lines.
Returns a PipelineResult describing the outcome of every stage.
"""

import time
from dataclasses import dataclass, field
from typing import Optional

import cti, file_reputation, mda, proxy, sanitiser
from logger import get_logger

log = get_logger("pipeline")


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class StageResult:
    name: str
    passed: bool
    duration_ms: float
    details: list[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class PipelineResult:
    url: str
    allowed: bool                           # Final verdict
    block_reason: Optional[str] = None
    risk_score: int = 0
    resolved_ip: Optional[str] = None
    stages: list[StageResult] = field(default_factory=list)
    content: Optional[sanitiser.SanitisedContent] = None
    total_ms: float = 0.0

    def summary(self) -> str:
        """Human-readable one-line summary."""
        verdict = "ALLOWED" if self.allowed else f"BLOCKED ({self.block_reason})"
        return (
            f"[{verdict}]  url={self.url!r}  "
            f"risk={self.risk_score}/100  "
            f"ip={self.resolved_ip}  "
            f"stages={len(self.stages)}  "
            f"total={self.total_ms:.0f}ms"
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _timed(fn, *args, **kwargs):
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    ms = (time.perf_counter() - t0) * 1000
    return result, ms


# ── Main entry point ──────────────────────────────────────────────────────────

def run(url: str) -> PipelineResult:
    """
    Run the full RBI pipeline for the given URL.
    Returns a PipelineResult with all stage outcomes and (if allowed) clean content.
    """
    t_start = time.perf_counter()
    stages: list[StageResult] = []
    result = PipelineResult(url=url, allowed=False)

    log.info("=" * 60)
    log.info(f"PIPELINE START  url={url!r}")
    log.info("=" * 60)

    # ── Normalise URL ──────────────────────────────────────────────
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        result.url = url

    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    domain = domain.replace("www.", "")

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 1: CTI Database — domain check (before fetching anything)
    # ─────────────────────────────────────────────────────────────────────────
    log.info("─── Stage 1: CTI DB (pre-fetch) ───")
    cti_pre, ms = _timed(cti.check, domain, None)
    stages.append(StageResult(
        name="CTI DB (domain pre-check)",
        passed=cti_pre.passed,
        duration_ms=ms,
        details=cti_pre.details,
        error=cti_pre.reason if not cti_pre.passed else None,
    ))
    result.risk_score = cti_pre.risk_score

    if not cti_pre.passed:
        result.block_reason = cti_pre.reason
        result.stages = stages
        result.total_ms = (time.perf_counter() - t_start) * 1000
        log.warning(f"PIPELINE BLOCKED at Stage 1: {cti_pre.reason}")
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 2: Proxy fetch (MiM — fetch content on behalf of client)
    # ─────────────────────────────────────────────────────────────────────────
    log.info("─── Stage 2: Proxy fetch (MiM) ───")
    fetch_result, ms = _timed(proxy.fetch, url)
    result.resolved_ip = fetch_result.resolved_ip

    if not fetch_result.success:
        stages.append(StageResult(
            name="Proxy fetch",
            passed=False,
            duration_ms=ms,
            error=fetch_result.error,
            details=[f"Fetch failed: {fetch_result.error}"],
        ))
        result.block_reason = f"Proxy fetch failed: {fetch_result.error}"
        result.stages = stages
        result.total_ms = (time.perf_counter() - t_start) * 1000
        log.warning(f"PIPELINE BLOCKED at Stage 2: {fetch_result.error}")
        return result

    stages.append(StageResult(
        name="Proxy fetch",
        passed=True,
        duration_ms=ms,
        details=[
            f"Fetched {len(fetch_result.raw_bytes):,} bytes",
            f"Status: {fetch_result.status_code}",
            f"Content-Type: {fetch_result.content_type}",
            f"Resolved IP: {fetch_result.resolved_ip}",
            f"Redirect chain: {' → '.join(fetch_result.redirect_chain)}",
        ],
    ))

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 3: CTI DB — re-check with resolved IP
    # ─────────────────────────────────────────────────────────────────────────
    log.info("─── Stage 3: CTI DB (IP check) ───")
    cti_post, ms = _timed(cti.check, domain, fetch_result.resolved_ip)
    result.risk_score = max(result.risk_score, cti_post.risk_score)
    stages.append(StageResult(
        name="CTI DB (IP post-check)",
        passed=cti_post.passed,
        duration_ms=ms,
        details=cti_post.details,
        error=cti_post.reason if not cti_post.passed else None,
    ))

    if not cti_post.passed:
        result.block_reason = cti_post.reason
        result.stages = stages
        result.total_ms = (time.perf_counter() - t_start) * 1000
        log.warning(f"PIPELINE BLOCKED at Stage 3: {cti_post.reason}")
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 4: File Reputation (SHA-256 + MD5 hash check)
    # ─────────────────────────────────────────────────────────────────────────
    log.info("─── Stage 4: File Reputation ───")
    fr, ms = _timed(file_reputation.check, fetch_result.raw_bytes)
    stages.append(StageResult(
        name="File Reputation",
        passed=fr.passed,
        duration_ms=ms,
        details=fr.details,
        error=fr.reason if not fr.passed else None,
    ))

    if not fr.passed:
        result.block_reason = fr.reason
        result.stages = stages
        result.total_ms = (time.perf_counter() - t_start) * 1000
        log.warning(f"PIPELINE BLOCKED at Stage 4: {fr.reason}")
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 5: MDA — SMA-256 / SMD-512 / phishing / IP reputation
    # ─────────────────────────────────────────────────────────────────────────
    log.info("─── Stage 5: MDA Analysis ───")

    # Extract raw text first (needed for phishing scan)
    raw_text = fetch_result.raw_bytes.decode(fetch_result.encoding, errors="replace")

    mda_result, ms = _timed(
        mda.check,
        fetch_result.raw_bytes,
        raw_text,
        domain,
        fetch_result.resolved_ip,
    )
    stages.append(StageResult(
        name="MDA (SMA-256 / SMD-512 / phishing / IP rep)",
        passed=mda_result.passed,
        duration_ms=ms,
        details=mda_result.details,
        error=mda_result.reason if not mda_result.passed else None,
    ))

    if not mda_result.passed:
        result.block_reason = mda_result.reason
        result.stages = stages
        result.total_ms = (time.perf_counter() - t_start) * 1000
        log.warning(f"PIPELINE BLOCKED at Stage 5: {mda_result.reason}")
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 6: HTML Sanitiser — strip all active content, extract text
    # ─────────────────────────────────────────────────────────────────────────
    log.info("─── Stage 6: HTML Sanitise & Render ───")
    clean, ms = _timed(sanitiser.sanitise, fetch_result.raw_bytes, fetch_result.encoding)
    stages.append(StageResult(
        name="HTML Sanitiser",
        passed=True,
        duration_ms=ms,
        details=[
            f"Title: {clean.title!r}",
            f"Text blocks: {len(clean.text_blocks)}",
            f"Words: {clean.word_count}",
            f"Stripped elements: {clean.stripped_elements}",
        ],
    ))

    # ── All checks passed ──
    result.allowed = True
    result.content = clean
    result.stages = stages
    result.total_ms = (time.perf_counter() - t_start) * 1000

    log.info(f"PIPELINE COMPLETE  {result.summary()}")
    return result
