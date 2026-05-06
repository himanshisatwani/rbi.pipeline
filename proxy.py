"""
rbi/core/proxy.py
Proxy Fetcher — the Man-in-the-Middle (MiM) layer.

Responsibilities:
  - Resolve domain → IP (DNS)
  - Open HTTP/HTTPS connection on behalf of the client
  - Return raw bytes + metadata (status, headers, resolved IP)
  - Never forward cookies or credentials from the real client
  - Strip all Set-Cookie headers from responses (cookie isolation)
  - Follow redirects (up to a limit) logging each hop
"""

import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

from logger import get_logger

log = get_logger("proxy")

from playwright.sync_api import sync_playwright

def fetch_rendered(url: str):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
        )

        page.goto(url, timeout=60000)
        content = page.content()

        browser.close()
        return content

MAX_REDIRECTS = 5
MAX_BYTES = 5 * 1024 * 1024   # 5 MB cap — text-only pages are small
TIMEOUT = 15                   # seconds
USER_AGENT = "RBI-Proxy/1.0 (RemoteBrowserIsolation; text-only)"


@dataclass
class FetchResult:
    success: bool
    url: str = ""
    resolved_ip: Optional[str] = None
    status_code: int = 0
    content_type: str = ""
    raw_bytes: bytes = b""
    encoding: str = "utf-8"
    redirect_chain: list[str] = field(default_factory=list)
    error: Optional[str] = None


def resolve_ip(domain: str) -> Optional[str]:
    """DNS resolution — returns first IPv4 address or None."""
    try:
        info = socket.getaddrinfo(domain, None, socket.AF_INET)
        ip = info[0][4][0]
        log.info(f"DNS: {domain!r} → {ip}")
        return ip
    except socket.gaierror as e:
        log.warning(f"DNS resolution failed for {domain!r}: {e}")
        return None
def fetch(url: str) -> FetchResult:
    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]

    log.info(f"Proxy fetch: {url!r}")

    # DNS resolve
    resolved_ip = resolve_ip(domain)

    redirect_chain = [url]

    try:
        html = fetch_rendered(url)

        log.info("  Rendered page fetched successfully")

        return FetchResult(
            success=True,
            url=url,
            resolved_ip=resolved_ip,
            status_code=200,
            content_type="text/html",
            raw_bytes=html.encode("utf-8"),
            encoding="utf-8",
            redirect_chain=redirect_chain,
        )

    except Exception as e:
        err = f"Render error: {e}"
        log.error(f"  Fetch exception: {err}")
        return FetchResult(
            success=False,
            url=url,
            resolved_ip=resolved_ip,
            error=err
        )  





def _parse_encoding(content_type: str) -> str:
    """Extract charset from Content-Type header, default utf-8."""
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            return part.split("=", 1)[1].strip().strip('"').lower()
    return "utf-8"
