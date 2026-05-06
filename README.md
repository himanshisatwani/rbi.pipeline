# RBI — Remote Browser Isolation

A Python backend implementing a **Remote Browser Isolation** security pipeline.
All web content is fetched server-side through a proxy (Man-in-the-Middle layer),
passed through a multi-stage security inspection pipeline, sanitised to text-only,
and delivered clean to the caller. No JavaScript, media, forms, or tracking ever
reaches the client.

---

## Architecture

```
Client request
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  LAYER 1 — Client / MiM intercept                   │
│  proxy.py  ──  DNS resolve  →  fetch via proxy      │
└───────────────────────┬─────────────────────────────┘
                        │ raw bytes
                        ▼
┌─────────────────────────────────────────────────────┐
│  LAYER 2 — Remote instance fetch                    │
│  Cookies stripped · UA spoofed · Redirects logged   │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│  LAYER 3 — Security inspection                      │
│                                                     │
│  ① CTI DB      domain + IP blacklist check          │
│  ② File Rep.   MD5 + SHA-256 hash match             │
│  ③ MDA         SMA-256 · SMD-512 · phishing · IP   │
│                                                     │
│  Any stage fail → request terminated immediately    │
└───────────────────────┬─────────────────────────────┘
                        │ clean bytes (if all pass)
                        ▼
┌─────────────────────────────────────────────────────┐
│  HTML Sanitiser                                     │
│  Strips: <script> <style> <iframe> <form> <img>     │
│          <object> <embed> event handlers data: URIs │
│  Keeps:  headings · paragraphs · lists · tables     │
└───────────────────────┬─────────────────────────────┘
                        │ text-only SanitisedContent
                        ▼
                   Caller / API
```

---

## Project layout

```
rbi/
├── rbi.py                  # CLI entrypoint
├── tests.py                # Unit + integration test suite (50 tests)
├── core/
│   ├── __init__.py
│   ├── pipeline.py         # Orchestrator — ties all stages together
│   ├── proxy.py            # MiM fetch layer (DNS + HTTP/HTTPS)
│   ├── cti.py              # CTI database checker
│   ├── file_reputation.py  # File hash reputation (MD5 / SHA-256)
│   ├── mda.py              # MDA: SMA-256, SMD-512, phishing, IP rep
│   ├── sanitiser.py        # HTML → safe text-only content
│   └── logger.py           # Structured logging (console + JSON file)
├── data/
│   └── cti_db.json         # Threat intelligence database
└── logs/
    └── rbi.log             # JSON-lines log output (auto-created)
```

---

## Requirements

- Python 3.10+ (uses `list[str]` type hints in dataclasses)
- **Zero external dependencies** — stdlib only:
  `hashlib · hmac · html.parser · http · json · logging · re · socket · ssl · urllib`

---

## Usage

### CLI

```bash
# Fetch and inspect a URL
python rbi.py https://en.wikipedia.org/wiki/Browser_isolation

# Domain shorthand (https:// added automatically)
python rbi.py oracle.com

# Verbose — show all stage details + full sanitised content
python rbi.py python.org --verbose

# JSON output (for piping into other tools / APIs)
python rbi.py oracle.com --json

# Run the built-in demo set (mix of safe and blocked URLs)
python rbi.py --demo
```

### Python API

```python
from core.pipeline import run

result = run("https://en.wikipedia.org/wiki/Browser_isolation")

if result.allowed:
    print(result.content.title)        # page title
    print(result.content.full_text)    # clean text
    print(result.content.word_count)   # word count
    print(result.risk_score)           # 0–100
else:
    print("BLOCKED:", result.block_reason)

# Inspect individual stage outcomes
for stage in result.stages:
    print(f"{stage.name}: {'PASS' if stage.passed else 'FAIL'} ({stage.duration_ms:.0f}ms)")
    for detail in stage.details:
        print(f"  {detail}")
```

### JSON output structure

```json
{
  "url": "https://oracle.com",
  "allowed": true,
  "block_reason": null,
  "risk_score": 2,
  "resolved_ip": "137.254.16.100",
  "total_ms": 412,
  "stages": [
    {
      "name": "CTI DB (domain pre-check)",
      "passed": true,
      "duration_ms": 0.4,
      "details": ["Domain 'oracle.com' is on the known-safe allowlist"],
      "error": null
    },
    ...
  ],
  "content": {
    "title": "Oracle — Integrated Cloud Applications",
    "word_count": 1842,
    "block_count": 94,
    "stripped_elements": 37,
    "text": "# Enterprise Software\n..."
  }
}
```

---

## Security stages in detail

### ① CTI Database (`core/cti.py`)

Checks against `data/cti_db.json`:

| Check | Description |
|---|---|
| Allowlist | Known-safe domains skip full pipeline (fast-path) |
| Domain blacklist | Exact match against known-malicious domains |
| IP blacklist | Resolved IP checked after fetch |
| Phishing patterns | Regex scan of page text for credential-harvesting language |
| Heuristic score | Suspicious TLDs (`.xyz`, `.bad`, `.evil`), long domains, numeric subdomains |

### ② File Reputation (`core/file_reputation.py`)

| Check | Description |
|---|---|
| MD5 | Content digest (logged, not used for blocking alone) |
| SHA-256 | Matched against `malicious_sha256` list in CTI DB |

### ③ MDA Analysis (`core/mda.py`)

| Check | Description |
|---|---|
| SMA-256 | HMAC-SHA256 of content with rotating proxy key |
| SMD-512 | SHA-512 structural message digest |
| Phishing scan | 10-pattern regex sweep on extracted text |
| IP reputation | Known Tor exit / abuse IP range detection |

### HTML Sanitiser (`core/sanitiser.py`)

Strips **all** of the following before returning content:

- `<script>` `<style>` `<noscript>` — no code execution
- `<iframe>` `<object>` `<embed>` `<applet>` — no embedded content
- `<form>` `<input>` `<button>` `<select>` `<textarea>` — no credential harvesting
- `<img>` `<video>` `<audio>` `<source>` `<track>` — no media (isolation)
- `<link>` `<meta>` `<base>` — no external resource loading
- `<svg>` `<canvas>` `<math>` — no rendering surfaces
- All `on*` event handler attributes
- All `javascript:` and `data:` URI schemes

---

## Adding to the CTI database

Edit `data/cti_db.json`:

```json
{
  "blacklisted_domains": ["new-threat.xyz"],
  "blacklisted_ips":     ["1.2.3.4"],
  "malicious_sha256":    ["abc123..."],
  "phishing_patterns":   ["new pattern.*here"],
  "known_safe_domains":  ["your-internal.corp"],
  "risk_scores":         {"your-internal.corp": 0}
}
```

No restart required — the database is read on every request.

---

## Running tests

```bash
python tests.py
```

```
Ran 50 tests in 0.115s
OK
```

Test coverage:
- `TestCTI` (9 tests) — allowlist, blacklist, IP block, heuristic scoring, phishing patterns
- `TestFileReputation` (6 tests) — hash correctness, malicious match, details output
- `TestMDA` (9 tests) — HMAC correctness, SHA-512, phishing detection, IP reputation
- `TestSanitiser` (16 tests) — script/form/iframe/img stripping, heading/list extraction, encoding
- `TestPipelineIntegration` (10 tests) — end-to-end blocked domains, stage sequencing, JSON shape

---

## Extending the project

| What | Where |
|---|---|
| Real CTI feed (VirusTotal, OTX) | Replace `cti.py` lookups with API calls |
| Persistent request log / audit trail | `logger.py` already writes JSON lines to `logs/rbi.log` |
| HTTP server / REST API | Wrap `pipeline.run()` in `http.server.BaseHTTPRequestHandler` |
| Rate limiting | Add token bucket in `proxy.py` before `fetch()` |
| Domain allowlist per-user | Add user context to `pipeline.run()`, filter in `cti.py` |
| YARA rule scanning | Add a stage after file reputation, before MDA |
| TLS certificate validation | Enable `ssl.CERT_REQUIRED` in `proxy.py` + bundle CA store |
