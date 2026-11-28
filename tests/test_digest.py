"""Offline tests for the email digest (no network: Zoho and the site are mocked)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_digest  # noqa: E402
import send_digest  # noqa: E402

BRIEF = {"edition": "2026-11-24", "executive": {"counts": {"kevAdded": 2}},
         "report": {"title": ["DAILY", "BRIEF"], "dateLabel": "Tuesday", "window": "w", "sourceNote": "s <b>",
                    "sections": [{"num": 1, "title": "Summary <script>", "blocks": [
                        {"type": "p", "text": "**Bold** & <img src=x onerror=alert(1)>"},
                        {"type": "table", "columns": ["A"], "rows": [["<i>x</i>"]]}]}],
                    "references": [{"label": "ok", "url": "https://nvd.nist.gov/x"},
                                   {"label": "bad", "url": "javascript:alert(1)"}]}}


class DigestTests(unittest.TestCase):
    def test_render_escapes_and_has_unsubscribe(self):
        subject, page = build_digest.render(BRIEF)
        self.assertIn("2 new exploited vulnerabilities", subject)
        self.assertIn("<strong>Bold</strong> &amp; &lt;img", page)
        self.assertNotIn("<script>", page)
        self.assertNotIn("javascript:", page)
        self.assertIn("$[LI:UNSUBSCRIBE]$", page)
        self.assertIn("tw-edition:2026-11-24", page)

    def test_not_configured_sends_nothing(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(sys, "argv", ["send_digest.py"]):
                self.assertEqual(send_digest.main(), 0)

    def test_zoho_flow(self):
        calls = []

        def fake(url, data=None, headers=None, timeout=30):
            calls.append((url, data, headers))
            if "tw-edition" not in "".join(str(x) for x in calls[-1]) and url.startswith("https://aegisdefensecyber.com"):
                return "<!-- tw-edition:2026-11-24 -->"
            if url.endswith("/oauth/v2/token"):
                return json.dumps({"access_token": "tok"})
            if "getmailinglists" in url:
                return json.dumps({"code": "200", "list_of_details": [
                    {"listname": "Other", "listkey": "NOPE"}, {"listname": "ThreatWatch Daily Brief", "listkey": "LISTKEY"}]})
            if url.endswith("createCampaign"):
                return json.dumps({"code": "200", "campaignKey": "123"})
            if url.endswith("sendcampaign"):
                return json.dumps({"code": "200", "campaign_status": "inprogress"})
            raise AssertionError(url)
        env = {n: "x" for n in send_digest.REQUIRED}   # no ZOHO_LIST_KEY: looked up by name
        env["ZOHO_FROM_EMAIL"] = "old@example.org"   # the config file's fromEmail wins
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(send_digest, "_request", fake), \
                mock.patch.object(send_digest, "EMAIL_DIR", Path(d)), \
                mock.patch.object(send_digest, "STATE_FILE", Path(d) / "digest-state.json"), \
                mock.patch.object(build_digest, "sender_identity", lambda: {"legalName": "Aegis Cyber Solutions LLC", "postalAddress": "1 Test St, Naples FL", "privacyUrl": "https://aegisdefensecyber.com/privacy/"}), \
                mock.patch.object(send_digest, "send_allowed", lambda *a, **k: (True, "test")), \
                mock.patch.object(send_digest, "read_json",
                                  lambda p, default=None: {"edition": "2026-11-24", "subject": "S",
                                                           "path": "threatwatch/email/2026-11-24.html"}), \
                mock.patch.object(sys, "argv", ["send_digest.py"]):
            self.assertEqual(send_digest.main(), 0)
        create = [c for c in calls if c[0].endswith("createCampaign")][0]
        self.assertEqual(json.loads(create[1]["list_details"]), {"LISTKEY": []})
        self.assertEqual(create[1]["content_url"], "https://aegisdefensecyber.com/threatwatch/email/2026-11-24.html")
        self.assertEqual(create[2]["Authorization"], "Zoho-oauthtoken tok")
        self.assertEqual(create[1]["from_email"], "threatwatch@aegisdefensecyber.com")
        self.assertTrue(any(c[0].endswith("sendcampaign") and c[1]["campaignkey"] == "123" for c in calls))

    def test_missing_postal_address_blocks_send(self):
        env = {n: "x" for n in send_digest.REQUIRED}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(build_digest, "sender_identity", lambda: {"legalName": "L", "postalAddress": "", "privacyUrl": ""}), \
                mock.patch.object(send_digest, "send_allowed", lambda *a, **k: (True, "test")), \
                mock.patch.object(send_digest, "_request", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network"))), \
                mock.patch.object(send_digest, "read_json",
                                  lambda p, default=None: {"edition": "2026-11-24", "subject": "S", "path": "p.html"}), \
                mock.patch.object(sys, "argv", ["send_digest.py"]):
            self.assertEqual(send_digest.main(), 1)

    def test_zoho_error_reports_failure(self):
        def fake(url, data=None, headers=None, timeout=30):
            if url.startswith("https://aegisdefensecyber.com"):
                return "tw-edition:2026-11-24"
            if url.endswith("/oauth/v2/token"):
                return json.dumps({"error": "invalid_code"})
            raise AssertionError(url)
        env = {n: "x" for n in send_digest.REQUIRED}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(send_digest, "_request", fake), \
                mock.patch.object(build_digest, "sender_identity", lambda: {"legalName": "Aegis Cyber Solutions LLC", "postalAddress": "1 Test St, Naples FL", "privacyUrl": "https://aegisdefensecyber.com/privacy/"}), \
                mock.patch.object(send_digest, "send_allowed", lambda *a, **k: (True, "test")), \
                mock.patch.object(send_digest, "read_json",
                                  lambda p, default=None: {"edition": "2026-11-24", "subject": "S", "path": "p.html"}), \
                mock.patch.object(sys, "argv", ["send_digest.py"]):
            self.assertEqual(send_digest.main(), 1)


class SendOncePerEditionTests(unittest.TestCase):
    """The morning email goes out once per edition, only 07:00-08:59 ET, unless a resend is forced."""

    def at(self, hhmm, day="2026-11-28"):
        from datetime import datetime
        from tw.common import ET
        return datetime.fromisoformat(f"{day}T{hhmm}:00").replace(tzinfo=ET)

    def test_window_and_once(self):
        ok = send_digest.send_allowed
        self.assertTrue(ok("2026-11-28", self.at("07:06"), {})[0])
        self.assertFalse(ok("2026-11-28", self.at("06:59"), {})[0])
        self.assertFalse(ok("2026-11-28", self.at("09:00"), {})[0])
        self.assertFalse(ok("2026-11-28", self.at("12:10"), {})[0])
        self.assertFalse(ok("2026-11-27", self.at("07:30"), {})[0])          # yesterday's edition
        sent = {"sent": {"2026-11-28": {"at": "2026-11-28T12:07:00Z"}}}
        self.assertFalse(ok("2026-11-28", self.at("07:40"), sent)[0])       # re-run never double-sends
        self.assertTrue(ok("2026-11-28", self.at("15:00"), sent, force=True)[0])

    def test_footer_has_identity_and_privacy(self):
        f = build_digest.identity_footer_html("#000")
        self.assertIn("Aegis Cyber Solutions LLC", f)
        self.assertIn("/privacy/", f)


if __name__ == "__main__":
    unittest.main()
