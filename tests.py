#!/usr/bin/env python3
"""
rbi/tests.py
Unit tests for all RBI pipeline stages.
Run: python tests.py
"""

import sys
import os
import hashlib
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import cti, file_reputation, mda, sanitiser
from core.pipeline import run


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

SAFE_HTML = b"""<html>
<head><title>Oracle Corporation</title></head>
<body>
  <h1>Enterprise Software</h1>
  <p>Oracle provides cloud infrastructure and applications.</p>
  <ul>
    <li>Oracle Database</li>
    <li>Oracle Cloud Infrastructure</li>
    <li>Java Platform</li>
  </ul>
  <h2>About</h2>
  <p>Founded in 1977, headquartered in Austin, Texas.</p>
  <script>document.cookie = 'track=1'</script>
  <img src="pixel.gif" width="1" height="1">
  <form action="/login"><input type="password"></form>
  <iframe src="https://evil.com"></iframe>
</body>
</html>"""

PHISHING_HTML = b"""<html><head><title>Bank Login</title></head>
<body>
  <p>Your account has been suspended. Please verify your bank account now.</p>
  <form action="/steal"><input type="password" placeholder="Enter password"></form>
</body>
</html>"""

PHISHING_TEXT = "Your account has been suspended. Please verify your bank account now."


# ─────────────────────────────────────────────────────────────────────────────
# CTI Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCTI(unittest.TestCase):

    def test_known_safe_domain_passes(self):
        r = cti.check("oracle.com")
        self.assertTrue(r.passed)
        self.assertLessEqual(r.risk_score, 10)

    def test_blacklisted_domain_blocked(self):
        r = cti.check("malware-site.bad")
        self.assertFalse(r.passed)
        self.assertGreaterEqual(r.risk_score, 90)
        self.assertIn("blacklist", r.reason.lower())

    def test_blacklisted_ip_blocked(self):
        r = cti.check("unknown-domain.com", "185.220.101.47")
        self.assertFalse(r.passed)
        self.assertIn("blacklist", r.reason.lower())

    def test_unknown_domain_passes_with_heuristic_score(self):
        r = cti.check("legit-company.com")
        self.assertTrue(r.passed)
        self.assertGreater(r.risk_score, 0)

    def test_suspicious_tld_scores_higher(self):
        r_xyz = cti.check("something.xyz")
        r_com = cti.check("something.com")
        self.assertGreater(r_xyz.risk_score, r_com.risk_score)

    def test_phishing_domain_blocked(self):
        r = cti.check("phishing-test.evil")
        self.assertFalse(r.passed)

    def test_wikipedia_allowlisted(self):
        r = cti.check("wikipedia.org")
        self.assertTrue(r.passed)
        self.assertLessEqual(r.risk_score, 5)

    def test_phishing_pattern_scan_detects(self):
        found, pattern = cti.check_phishing_patterns(PHISHING_TEXT)
        self.assertTrue(found)
        self.assertIsNotNone(pattern)

    def test_phishing_pattern_scan_clean(self):
        found, pattern = cti.check_phishing_patterns("Oracle provides enterprise software.")
        self.assertFalse(found)
        self.assertIsNone(pattern)


# ─────────────────────────────────────────────────────────────────────────────
# File Reputation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFileReputation(unittest.TestCase):

    def test_safe_content_passes(self):
        r = file_reputation.check(SAFE_HTML)
        self.assertTrue(r.passed)
        self.assertNotEqual(r.md5, "")
        self.assertNotEqual(r.sha256, "")

    def test_md5_correct_length(self):
        r = file_reputation.check(b"hello world")
        self.assertEqual(len(r.md5), 32)

    def test_sha256_correct_length(self):
        r = file_reputation.check(b"hello world")
        self.assertEqual(len(r.sha256), 64)

    def test_known_malicious_hash_blocked(self):
        # Empty file SHA-256 is in the test blacklist
        r = file_reputation.check(b"")
        self.assertFalse(r.passed)
        self.assertIn("malicious", r.reason.lower())

    def test_different_content_different_hashes(self):
        r1 = file_reputation.check(b"content A")
        r2 = file_reputation.check(b"content B")
        self.assertNotEqual(r1.sha256, r2.sha256)
        self.assertNotEqual(r1.md5, r2.md5)

    def test_result_has_details(self):
        r = file_reputation.check(SAFE_HTML)
        self.assertGreater(len(r.details), 0)
        self.assertTrue(any("SHA-256" in d for d in r.details))
        self.assertTrue(any("MD5" in d for d in r.details))


# ─────────────────────────────────────────────────────────────────────────────
# MDA Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestMDA(unittest.TestCase):

    def test_safe_content_passes(self):
        r = mda.check(SAFE_HTML, "Enterprise Software Oracle", "oracle.com", "137.254.16.1")
        self.assertTrue(r.passed)
        self.assertFalse(r.phishing_detected)
        self.assertNotEqual(r.sma256, "")
        self.assertNotEqual(r.smd512, "")

    def test_phishing_text_blocked(self):
        r = mda.check(PHISHING_HTML, PHISHING_TEXT, "evil-bank.xyz", "1.2.3.4")
        self.assertFalse(r.passed)
        self.assertTrue(r.phishing_detected)
        self.assertIn("phishing", r.reason.lower())

    def test_sma256_is_hmac_sha256(self):
        import hmac, hashlib
        content = b"test content"
        secret = b"rbi-proxy-isolation-key-2024"
        expected = hmac.new(secret, content, hashlib.sha256).hexdigest()
        r = mda.check(content, "test content", "example.com")
        self.assertEqual(r.sma256, expected)

    def test_smd512_is_sha512(self):
        content = b"test content"
        expected = hashlib.sha512(content).hexdigest()
        r = mda.check(content, "test content", "example.com")
        self.assertEqual(r.smd512, expected)

    def test_suspicious_ip_flagged(self):
        r = mda.check(SAFE_HTML, "safe text", "example.com", "185.220.10.1")
        # Suspicious IP gets flagged in details but doesn't hard-block
        self.assertTrue(any("SUSPICIOUS" in d or "suspicious" in d.lower() for d in r.details))

    def test_internal_ip_recognised(self):
        r = mda.check(SAFE_HTML, "safe text", "localhost", "127.0.0.1")
        self.assertEqual(r.ip_reputation, "INTERNAL")

    def test_clean_ip_reputation(self):
        r = mda.check(SAFE_HTML, "safe text", "oracle.com", "137.254.16.1")
        self.assertEqual(r.ip_reputation, "CLEAN")

    def test_sma256_length(self):
        r = mda.check(b"data", "data", "x.com")
        self.assertEqual(len(r.sma256), 64)

    def test_smd512_length(self):
        r = mda.check(b"data", "data", "x.com")
        self.assertEqual(len(r.smd512), 128)


# ─────────────────────────────────────────────────────────────────────────────
# Sanitiser Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSanitiser(unittest.TestCase):

    def test_title_extracted(self):
        s = sanitiser.sanitise(SAFE_HTML)
        self.assertEqual(s.title, "Oracle Corporation")

    def test_script_stripped(self):
        s = sanitiser.sanitise(SAFE_HTML)
        self.assertNotIn("document.cookie", s.full_text)
        self.assertNotIn("cookie", s.full_text)

    def test_form_stripped(self):
        s = sanitiser.sanitise(SAFE_HTML)
        self.assertNotIn("password", s.full_text)

    def test_iframe_stripped(self):
        s = sanitiser.sanitise(SAFE_HTML)
        self.assertNotIn("evil.com", s.full_text)

    def test_img_stripped(self):
        s = sanitiser.sanitise(SAFE_HTML)
        self.assertNotIn("pixel.gif", s.full_text)

    def test_headings_preserved(self):
        s = sanitiser.sanitise(SAFE_HTML)
        headings = [b for b in s.text_blocks if b.startswith("#")]
        self.assertGreaterEqual(len(headings), 1)
        self.assertTrue(any("Enterprise Software" in h for h in headings))

    def test_paragraphs_preserved(self):
        s = sanitiser.sanitise(SAFE_HTML)
        self.assertIn("Oracle provides cloud infrastructure", s.full_text)

    def test_list_items_preserved(self):
        s = sanitiser.sanitise(SAFE_HTML)
        bullets = [b for b in s.text_blocks if b.startswith("•")]
        self.assertGreaterEqual(len(bullets), 3)
        self.assertTrue(any("Oracle Database" in b for b in bullets))

    def test_word_count_positive(self):
        s = sanitiser.sanitise(SAFE_HTML)
        self.assertGreater(s.word_count, 0)

    def test_stripped_elements_counted(self):
        s = sanitiser.sanitise(SAFE_HTML)
        # script, img, form, iframe = at least 3 top-level dropped tags
        # (input inside form is not double-counted — already in dropped subtree)
        self.assertGreaterEqual(s.stripped_elements, 3)

    def test_empty_content(self):
        s = sanitiser.sanitise(b"<html><body></body></html>")
        self.assertEqual(s.word_count, 0)
        self.assertEqual(s.text_blocks, [])

    def test_plain_text_passthrough(self):
        s = sanitiser.sanitise(b"Hello world. Just plain text.")
        self.assertIn("Hello world", s.full_text)

    def test_no_javascript_in_output(self):
        html = b"<p>Safe</p><script>alert('xss')</script><p>Also safe</p>"
        s = sanitiser.sanitise(html)
        self.assertNotIn("alert", s.full_text)
        self.assertNotIn("xss", s.full_text)

    def test_event_handlers_stripped(self):
        html = b'<p onclick="steal()">Click me</p>'
        s = sanitiser.sanitise(html)
        self.assertNotIn("steal()", s.full_text)
        self.assertIn("Click me", s.full_text)

    def test_nested_script_in_dropped_tag(self):
        html = b"<noscript><script>evil()</script></noscript><p>Visible</p>"
        s = sanitiser.sanitise(html)
        self.assertNotIn("evil", s.full_text)
        self.assertIn("Visible", s.full_text)

    def test_encoding_fallback(self):
        # Latin-1 encoded content
        html = "Héllo wörld".encode("latin-1")
        s = sanitiser.sanitise(html, encoding="latin-1")
        self.assertIn("H", s.full_text)


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline Integration Tests (no network — blocked domains only)
# ─────────────────────────────────────────────────────────────────────────────

class TestPipelineIntegration(unittest.TestCase):

    def test_blacklisted_domain_blocked_at_stage1(self):
        r = run("malware-site.bad")
        self.assertFalse(r.allowed)
        self.assertIsNotNone(r.block_reason)
        self.assertEqual(len(r.stages), 1)
        self.assertFalse(r.stages[0].passed)

    def test_phishing_domain_blocked(self):
        r = run("phishing-test.evil")
        self.assertFalse(r.allowed)
        self.assertGreaterEqual(r.risk_score, 90)

    def test_blacklisted_ip_domain(self):
        r = run("c2-beacon.bad")
        self.assertFalse(r.allowed)

    def test_result_has_url(self):
        r = run("malware-site.bad")
        self.assertIn("malware-site.bad", r.url)

    def test_result_has_stages(self):
        r = run("malware-site.bad")
        self.assertGreater(len(r.stages), 0)

    def test_stage_has_duration(self):
        r = run("malware-site.bad")
        for s in r.stages:
            self.assertGreaterEqual(s.duration_ms, 0)

    def test_total_ms_positive(self):
        r = run("malware-site.bad")
        self.assertGreater(r.total_ms, 0)

    def test_allowlisted_domain_passes_cti(self):
        r = run("oracle.com")
        # CTI stage should pass (network will fail, but that's stage 2)
        cti_stage = r.stages[0]
        self.assertTrue(cti_stage.passed)

    def test_url_normalised(self):
        r = run("malware-site.bad")
        self.assertTrue(r.url.startswith("https://"))

    def test_summary_string(self):
        r = run("malware-site.bad")
        summary = r.summary()
        self.assertIn("BLOCKED", summary)
        self.assertIn("malware-site.bad", summary)


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import hashlib  # already imported at top but needed in test scope
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    for cls in [TestCTI, TestFileReputation, TestMDA, TestSanitiser, TestPipelineIntegration]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
