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
            if url.endswith("createCampaign"):
                return json.dumps({"code": "200", "campaignKey": "123"})
            if url.endswith("sendcampaign"):
                return json.dumps({"code": "200", "campaign_status": "inprogress"})
            raise AssertionError(url)
        env = {n: "x" for n in send_digest.REQUIRED}
        env["ZOHO_LIST_KEY"] = "LISTKEY"
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(send_digest, "_request", fake), \
                mock.patch.object(send_digest, "EMAIL_DIR", Path(d)), \
                mock.patch.object(send_digest, "read_json",
                                  lambda p, default=None: {"edition": "2026-11-24", "subject": "S",
                                                           "path": "threatwatch/email/2026-11-24.html"}), \
                mock.patch.object(sys, "argv", ["send_digest.py"]):
            self.assertEqual(send_digest.main(), 0)
        create = [c for c in calls if c[0].endswith("createCampaign")][0]
        self.assertEqual(json.loads(create[1]["list_details"]), {"LISTKEY": []})
        self.assertEqual(create[1]["content_url"], "https://aegisdefensecyber.com/threatwatch/email/2026-11-24.html")
        self.assertEqual(create[2]["Authorization"], "Zoho-oauthtoken tok")
        self.assertTrue(any(c[0].endswith("sendcampaign") and c[1]["campaignkey"] == "123" for c in calls))

    def test_zoho_error_reports_failure(self):
        def fake(url, data=None, headers=None, timeout=30):
            if url.startswith("https://aegisdefensecyber.com"):
                return "tw-edition:2026-11-24"
            if url.endswith("/oauth/v2/token"):
                return json.dumps({"error": "invalid_code"})
            raise AssertionError(url)
        env = {n: "x" for n in send_digest.REQUIRED}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(send_digest, "_request", fake), \
                mock.patch.object(send_digest, "read_json",
                                  lambda p, default=None: {"edition": "2026-11-24", "subject": "S", "path": "p.html"}), \
                mock.patch.object(sys, "argv", ["send_digest.py"]):
            self.assertEqual(send_digest.main(), 1)


if __name__ == "__main__":
    unittest.main()
