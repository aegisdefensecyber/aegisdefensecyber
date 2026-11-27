import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_watch import adv_hits, adv_significant, compile_watch, cve_hits  # noqa: E402

W = compile_watch({"id": "databases", "name": "Databases", "vendors": ["Oracle", "Check Point", "HP"], "products": ["Java", "OpenJDK"],
                   "cves": ["CVE-2026-114938"], "keywords": ["Critical Patch Update"], "exclude": ["Azure Linux"],
                   "advisorySources": ["oracle"]})


class WatchMatchTest(unittest.TestCase):
    def test_cves_whole_words_and_compact(self):
        self.assertTrue(cve_hits(W, {"cve": "CVE-1", "vendor": "Oracle", "product": "MySQL"}))
        self.assertTrue(cve_hits(W, {"cve": "CVE-2", "vendor": "Red Hat", "product": "OpenJDK 21"}))
        self.assertTrue(cve_hits(W, {"cve": "CVE-3", "vendor": "checkpoint", "product": "Gaia"}))
        self.assertTrue(cve_hits(W, {"cve": "CVE-4", "vendor": "Hewlett Packard (HP)", "product": "x"}))
        self.assertFalse(cve_hits(W, {"cve": "CVE-5", "vendor": "Php", "product": "php"}))       # 'hp' is not 'php'
        self.assertFalse(cve_hits(W, {"cve": "CVE-6", "vendor": "Checkmk", "product": "Checkmk"}))
        self.assertFalse(cve_hits(W, {"cve": "CVE-7", "vendor": "Microsoft", "product": "Azure Linux"}))
        self.assertTrue(cve_hits(W, {"cve": "CVE-2026-114938", "vendor": "x", "product": "y"}))

    def test_advisories(self):
        self.assertTrue(adv_hits(W, {"src": "oracle", "vendor": "Oracle", "title": "anything"}))
        self.assertTrue(adv_hits(W, {"src": "csaf_cisco", "vendor": "Hitachi", "title": "Cosminexus", "cves": ["CVE-2026-114938"]}))
        self.assertFalse(adv_hits(W, {"src": "certfr_avis", "vendor": "Oracle", "title": "Vulnérabilité dans Oracle"}))   # republisher
        self.assertFalse(adv_hits(W, {"src": "osv_ubuntu", "vendor": "Ubuntu", "title": "openjdk"}))
        self.assertTrue(adv_significant({"sev": "HIGH"}, set()))
        self.assertFalse(adv_significant({"sev": "HIGH"}, set(), "critical"))
        self.assertTrue(adv_significant({"sev": "MEDIUM", "cves": ["CVE-9"]}, {"CVE-9"}, "critical"))


if __name__ == "__main__":
    unittest.main()
