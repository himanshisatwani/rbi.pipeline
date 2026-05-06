#!/usr/bin/env python3
"""
rbi/rbi.py
Remote Browser Isolation — CLI entrypoint.

Usage:
    python rbi.py <url>
    python rbi.py <url> --json
    python rbi.py <url> --verbose
    python rbi.py --demo          # runs a set of test URLs
"""

import sys
import json
import argparse
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline import run, PipelineResult
from logger import get_logger

log = get_logger("rbi.cli")

ANSI = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "red":    "\033[31m",
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "cyan":   "\033[36m",
    "grey":   "\033[90m",
    "white":  "\033[97m",
}

def c(color: str, text: str) -> str:
    """Wrap text in ANSI color if stdout is a tty."""
    if not sys.stdout.isatty():
        return text
    return ANSI.get(color, "") + text + ANSI["reset"]


def print_result(result: PipelineResult, verbose: bool = False) -> None:
    print()
    print(c("bold", "━" * 60))
    print(c("bold", f"  RBI Pipeline Result"))
    print(c("bold", "━" * 60))
    print(f"  URL      : {c('cyan', result.url)}")
    print(f"  IP       : {result.resolved_ip or 'N/A'}")
    print(f"  Risk     : {_risk_color(result.risk_score)}")
    print(f"  Total    : {result.total_ms:.0f} ms")
    print()

    # Stage table
    print(c("grey", f"  {'STAGE':<40} {'STATUS':<10} {'MS':>6}"))
    print(c("grey", "  " + "─" * 58))
    for s in result.stages:
        status = c("green", "PASS") if s.passed else c("red", "FAIL")
        name   = s.name[:38]
        print(f"  {name:<40} {status:<10} {s.duration_ms:>6.0f}")
        if verbose or not s.passed:
            for d in s.details:
                print(c("grey", f"    ↳ {d}"))
            if s.error:
                print(c("red", f"    ✗ {s.error}"))
    print()

    # Verdict
    if result.allowed:
        print(c("green", c("bold", "  ✓ ACCESS ALLOWED — content delivered")))
        print()
        if result.content:
            _print_content(result.content, verbose)
    else:
        print(c("red", c("bold", f"  ✗ ACCESS BLOCKED")))
        print(c("red", f"    Reason: {result.block_reason}"))

    print()
    print(c("bold", "━" * 60))


def _risk_color(score: int) -> str:
    if score <= 20:
        return c("green", f"{score}/100 LOW")
    elif score <= 60:
        return c("yellow", f"{score}/100 MEDIUM")
    else:
        return c("red", f"{score}/100 HIGH")


def _print_content(content, verbose: bool) -> None:
    print(c("bold", f"  ── Sanitised Content ──────────────────────"))
    print(f"  Title : {content.title}")
    print(f"  Words : {content.word_count}")
    print(f"  Blocks: {len(content.text_blocks)}")
    print(f"  Stripped elements: {content.stripped_elements}")
    print()

    # Print up to first 20 text blocks (or all if verbose)
    limit = None if verbose else 20
    blocks = content.text_blocks[:limit]
    for block in blocks:
        # Trim long lines
        line = block if len(block) <= 120 else block[:117] + "…"
        print(f"  {c('grey', line)}")
    if not verbose and len(content.text_blocks) > 20:
        remaining = len(content.text_blocks) - 20
        print(c("grey", f"  … {remaining} more blocks (use --verbose to see all)"))


def to_json(result: PipelineResult) -> dict:
    return {
        "url": result.url,
        "allowed": result.allowed,
        "block_reason": result.block_reason,
        "risk_score": result.risk_score,
        "resolved_ip": result.resolved_ip,
        "total_ms": round(result.total_ms, 2),
        "stages": [
            {
                "name": s.name,
                "passed": s.passed,
                "duration_ms": round(s.duration_ms, 2),
                "details": s.details,
                "error": s.error,
            }
            for s in result.stages
        ],
        "content": {
            "title": result.content.title,
            "word_count": result.content.word_count,
            "block_count": len(result.content.text_blocks),
            "stripped_elements": result.content.stripped_elements,
            "text": result.content.full_text,
        } if result.content else None,
    }


DEMO_URLS = [
    "https://en.wikipedia.org/wiki/Browser_isolation",
    "https://python.org",
    "malware-site.bad",          # will be blocked at CTI stage
    "phishing-test.evil",        # will be blocked at CTI stage
]


def main():
    parser = argparse.ArgumentParser(
        prog="rbi",
        description="Remote Browser Isolation — security pipeline",
    )
    parser.add_argument("url", nargs="?", help="URL or domain to fetch")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of human-readable")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all stage details and full content")
    parser.add_argument("--demo", action="store_true", help="Run demo URLs")
    args = parser.parse_args()

    urls = []
    if args.demo:
        urls = DEMO_URLS
    elif args.url:
        urls = [args.url]
    else:
        parser.print_help()
        sys.exit(1)

    for url in urls:
        result = run(url)
        if args.json:
            print(json.dumps(to_json(result), indent=2))
        else:
            print_result(result, verbose=args.verbose)


if __name__ == "__main__":
    main()
