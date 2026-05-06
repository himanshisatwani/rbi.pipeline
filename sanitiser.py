"""
rbi/core/sanitiser.py
HTML Sanitiser — the final rendering layer.

Strips ALL active/executable content from fetched HTML and returns
clean, text-only structured output safe to deliver to the client.

Removes:
  - <script>, <style>, <iframe>, <object>, <embed>, <applet>
  - All event handlers (onclick, onload, onerror, …)
  - All href="javascript:…" and src="data:…"
  - All <form> elements (prevents credential harvesting relay)
  - All <img>, <video>, <audio> (media isolation)
  - All <link> (external resource loading)
  - All <meta http-equiv="refresh"> (redirect prevention)
  - Tracking pixels (1x1 images)

Retains (text-only mode):
  - Heading structure (h1–h6) → plain text with prefix
  - Paragraphs
  - Lists (ul/ol/li)
  - Tables → plain text rows
  - <pre>/<code> blocks
"""

import re
import html
from html.parser import HTMLParser
from dataclasses import dataclass
from typing import Optional

from logger import get_logger

log = get_logger("sanitiser")

# Tags whose entire subtree is dropped
_DROP_TAGS = {
    "script", "style", "iframe", "object", "embed", "applet",
    "form", "input", "button", "select", "textarea",
    "img", "image", "video", "audio", "source", "track",
    "link", "meta", "base", "noscript",
    "svg", "math", "canvas",
}

# Void elements — no closing tag, so we must not hold skip_depth open
_VOID_DROP_TAGS = {"img", "image", "input", "link", "meta", "base", "source", "track"}
_BLOCK_TAGS = {"p", "div", "section", "article", "main", "aside", "header",
               "footer", "nav", "figure", "figcaption", "blockquote",
               "ul", "ol", "dl", "table", "tbody", "thead", "tfoot"}

_HEADING_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6"}

# Strip all on* attributes and dangerous protocols
_DANGEROUS_ATTR_RE = re.compile(r'\bon\w+\s*=', re.IGNORECASE)
_DANGEROUS_PROTO_RE = re.compile(r'(javascript|vbscript|data):', re.IGNORECASE)


@dataclass
class SanitisedContent:
    title: str
    text_blocks: list[str]
    full_text: str
    word_count: int
    stripped_elements: int


class _TextExtractor(HTMLParser):
    """Stateful parser that walks HTML and collects safe text."""

    def __init__(self):
        super().__init__()
        self._skip_depth = 0          # inside a dropped tag subtree
        self._current_tag = ""
        self.title = ""
        self.blocks: list[str] = []
        self._buf = []                 # current inline text buffer
        self._in_title = False
        self._stripped = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self._skip_depth > 0:
            self._skip_depth += 1
            return
        if tag in _VOID_DROP_TAGS:
            # Void element — count as stripped but don't open a skip subtree
            self._stripped += 1
            return
        if tag in _DROP_TAGS:
            self._skip_depth += 1
            self._stripped += 1
            return
        # Flush buffer on block boundaries
        if tag in _BLOCK_TAGS or tag in _HEADING_TAGS or tag in {"tr", "dt", "dd"}:
            self._flush()
        if tag in _HEADING_TAGS:
            level = int(tag[1])
            self._buf.append("#" * level + " ")
        if tag == "li":
            self._flush()          # flush previous li content first
            self._buf.append("• ")
        if tag == "br":
            self._buf.append("\n")
        if tag == "title":
            self._in_title = True
        self._current_tag = tag

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if tag in _BLOCK_TAGS or tag in _HEADING_TAGS or tag in {"li", "tr", "p", "dt", "dd"}:
            self._flush()
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._skip_depth > 0:
            return
        text = data.strip()
        if not text:
            return
        if self._in_title:
            self.title = text
            return
        self._buf.append(text)

    def _flush(self):
        line = " ".join(self._buf).strip()
        if line:
            self.blocks.append(line)
        self._buf = []

    def finish(self):
        self._flush()


def sanitise(raw_html: bytes, encoding: str = "utf-8") -> SanitisedContent:
    """
    Parse raw HTML bytes, strip all dangerous content, return clean text.
    """
    try:
        source = raw_html.decode(encoding, errors="replace")
    except Exception:
        source = raw_html.decode("latin-1", errors="replace")

    # Pre-strip dangerous attributes with regex before parsing
    source = _DANGEROUS_ATTR_RE.sub("data-rbi-stripped=", source)

    parser = _TextExtractor()
    try:
        parser.feed(source)
    except Exception as e:
        log.warning(f"Parser error (continuing): {e}")
    parser.finish()

    blocks = [b for b in parser.blocks if b.strip()]
    full_text = "\n".join(blocks)
    word_count = len(full_text.split())

    log.info(
        f"Sanitised: title={parser.title!r}  "
        f"blocks={len(blocks)}  words={word_count}  "
        f"stripped_elements={parser._stripped}"
    )

    return SanitisedContent(
        title=parser.title or "(no title)",
        text_blocks=blocks,
        full_text=full_text,
        word_count=word_count,
        stripped_elements=parser._stripped,
    )
