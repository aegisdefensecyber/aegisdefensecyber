"""Human-review gate for AI-drafted briefings (publish_briefing.py / approve_briefing.py)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def briefing(**k):
    b = {"date": "2026-11-28", "watch": "linux", "watchName": "Linux distributions", "priority": "HIGH",
         "title": "Linux — Threat Intelligence Update", "headline": "A headline.", "judgment": "A judgment.",
         "sources": [{"title": "Vendor", "url": "https://example.com/advisory"}],
         "draftedBy": "AI-drafted by Claude (test)"}
    b.update(k)
    return b


class BriefingReviewGate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = dict(os.environ, TW_DATA_DIR=str(self.tmp))

    def run_py(self, *args):
        return subprocess.run([sys.executable, *args], cwd=ROOT, env=self.env, capture_output=True, text=True)

    def write(self, b):
        p = self.tmp / "in.json"
        p.write_text(json.dumps(b))
        return str(p)

    def test_unreviewed_publish_is_refused(self):
        r = self.run_py("scripts/publish_briefing.py", self.write(briefing()))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("review.status", r.stderr)

    def test_draft_then_approve(self):
        r = self.run_py("scripts/publish_briefing.py", "--draft", self.write(briefing()))
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads((self.tmp / "briefings" / "2026-11-28-linux.json").read_text())
        self.assertEqual(out["review"], {"status": "pending"})
        self.assertEqual(out["draftedBy"], "AI-drafted by Claude (test)")
        r = self.run_py("scripts/approve_briefing.py", "--editor", "Test Editor", "2026-11-28-linux.json")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads((self.tmp / "briefings" / "2026-11-28-linux.json").read_text())
        self.assertEqual(out["review"]["status"], "reviewed")
        self.assertEqual(out["review"]["by"], "Test Editor")
        idx = json.loads((self.tmp / "briefings" / "index.json").read_text())
        self.assertEqual(idx["briefings"][0]["review"], "reviewed")

    def test_draftedby_required(self):
        b = briefing()
        del b["draftedBy"]
        r = self.run_py("scripts/publish_briefing.py", "--draft", self.write(b))
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
