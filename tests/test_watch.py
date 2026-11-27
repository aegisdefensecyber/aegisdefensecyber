import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_watch import matches_adv, matches_cve  # noqa: E402

W = {"id": "oracle-java", "name": "Oracle & Java", "vendors": ["oracle"], "products": ["java", "openjdk"],
     "cves": ["CVE-2026-114938"], "keywords": ["Critical Patch Update"]}


class WatchMatchTest(unittest.TestCase):
    def test_cves(self):
        self.assertTrue(matches_cve(W, {"cve": "CVE-2026-1", "vendor": "Oracle", "product": "MySQL"}))
        self.assertTrue(matches_cve(W, {"cve": "CVE-2026-2", "vendor": "Red Hat", "product": "OpenJDK 21"}))
        self.assertTrue(matches_cve(W, {"cve": "CVE-2026-114938", "vendor": "x", "product": "y"}))
        self.assertFalse(matches_cve(W, {"cve": "CVE-2026-3", "vendor": "Cisco", "product": "IOS"}))

    def test_advisories(self):
        ids = {"CVE-2026-114938", "CVE-2026-2"}
        self.assertTrue(matches_adv(W, {"vendor": "Red Hat", "title": "OpenJDK update", "products": ["java-21-openjdk"], "cves": ["CVE-2026-2"]}, ids))
        self.assertTrue(matches_adv(W, {"vendor": "Hitachi", "title": "Cosminexus", "cves": ["CVE-2026-114938"]}, ids))
        self.assertTrue(matches_adv(W, {"vendor": "Oracle", "title": "Oracle Critical Patch Update - January 2027", "cves": []}, ids))
        self.assertFalse(matches_adv(W, {"vendor": "Cisco", "title": "IOS XE", "cves": ["CVE-2026-9"]}, ids))


if __name__ == "__main__":
    unittest.main()
