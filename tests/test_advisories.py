import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tw.advisories import parse_csaf, parse_fortinet_rss, parse_ghsa, parse_panw  # noqa: E402
from tw.products import build as build_products  # noqa: E402

CSAF = {
    "document": {
        "title": "Visio RCE", "distribution": {"tlp": {"label": "WHITE"}},
        "publisher": {"name": "Microsoft Security Response Center"},
        "tracking": {"id": "msrc_CVE-2026-123903", "initial_release_date": "2026-11-24T08:00:00Z",
                     "current_release_date": "2026-11-24T08:00:00Z"},
        "references": [{"category": "self", "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-123903"},
                       {"category": "self", "url": "https://msrc.microsoft.com/csaf/advisories/2026/x.json"}],
    },
    "product_tree": {"branches": [{"category": "vendor", "name": "Microsoft", "branches": [
        {"category": "product_name", "name": "Office", "branches": [
            {"category": "product_version_range", "name": "<16.0.1", "product": {"name": "Microsoft Office <16.0.1", "product_id": "4"}}]}]}]},
    "vulnerabilities": [{
        "cve": "CVE-2026-123903", "title": "Microsoft Office Visio Remote Code Execution Vulnerability",
        "scores": [{"cvss_v3": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
        "product_status": {"known_affected": ["4"], "fixed": ["5"]},
        "remediations": [{"category": "vendor_fix", "details": "16.0.1:Security Update", "url": "https://learn.microsoft.com/x"},
                         {"category": "vendor_fix", "details": "bad", "url": "javascript:alert(1)"}],
        "threats": [{"category": "exploit_status", "details": "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"}],
        "notes": [{"category": "description", "text": "RCE in Visio."}],
    }],
}


class CsafTest(unittest.TestCase):
    def test_parse(self):
        a = parse_csaf(CSAF, "https://msrc.microsoft.com/csaf/advisories/2026/x.json")[0]
        self.assertEqual((a["cve"], a["vendor"], a["cvss"], a["severity"], a["exploited"]),
                         ("CVE-2026-123903", "Microsoft", 9.8, "CRITICAL", True))
        self.assertEqual(a["url"], "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-123903")
        self.assertEqual(a["products"], ["Microsoft Office <16.0.1"])
        self.assertEqual(a["fixes"][0]["url"], "https://learn.microsoft.com/x")
        self.assertIsNone(a["fixes"][1]["url"])          # unsafe link dropped

    def test_restricted_tlp_skipped(self):
        doc = {**CSAF, "document": {**CSAF["document"], "distribution": {"tlp": {"label": "AMBER"}}}}
        self.assertEqual(parse_csaf(doc), [])


class FeedsTest(unittest.TestCase):
    def test_ghsa(self):
        a = parse_ghsa({"ghsa_id": "GHSA-xxxx", "cve_id": "CVE-2026-1111", "summary": "Bad", "severity": "high",
                        "html_url": "https://github.com/advisories/GHSA-xxxx", "published_at": "2026-11-20T00:00:00Z",
                        "updated_at": "2026-11-21T00:00:00Z", "cvss": {"score": 8.1},
                        "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "left-pad"},
                                             "vulnerable_version_range": "< 1.2.0", "first_patched_version": "1.2.0"}]})
        self.assertEqual((a["cve"], a["severity"], a["cvss"]), ("CVE-2026-1111", "HIGH", 8.1))
        self.assertIn("1.2.0", a["fixes"][0]["text"])
        self.assertIsNone(parse_ghsa({"ghsa_id": "GHSA-y", "cve_id": None}))

    def test_fortinet(self):
        xml = ("<rss><channel><item><title>NGINX vulnerabilities</title><link>https://fortiguard.fortinet.com/psirt/FG-IR-26-279</link>"
               "<description>&lt;p&gt;CVSSv3 Score: 8.1&lt;/p&gt; CVE-2026-123007 (high) affects NGINX</description>"
               "<pubDate>Fri, 20 Nov 2026 00:00:00 -0700</pubDate></item></channel></rss>")
        a = parse_fortinet_rss(xml)[0]
        self.assertEqual((a["cve"], a["vendor"], a["cvss"], a["id"]), ("CVE-2026-123007", "Fortinet", 8.1, "FG-IR-26-279"))

    def test_panw(self):
        a = parse_panw([{"ID": "CVE-2026-0300", "title": "PAN-OS: issue", "date": "2026-11-20T00:00:00Z", "baseScore": 9.3,
                         "baseSeverity": "CRITICAL", "product": ["PAN-OS"], "solution": [{"value": "Upgrade to 11.2.4"}],
                         "exploit": [{"value": "Palo Alto Networks is aware of limited exploitation of this issue."}]}])[0]
        self.assertEqual((a["cve"], a["exploited"], a["url"]), ("CVE-2026-0300", True, "https://security.paloaltonetworks.com/CVE-2026-0300"))


class ProductsTest(unittest.TestCase):
    def test_major_vendors_only(self):
        import json
        import tempfile
        recs = {f"CVE-2026-{i:04d}": {"affected": [{"vendor": "microsoft", "product": "exchange_server"}], "kev": None} for i in range(4)}
        recs["CVE-2026-9999"] = {"affected": [{"vendor": "tinyco", "product": "widget"}], "kev": None}
        recs["CVE-2026-8888"] = {"affected": [], "vendor": "Ivanti", "product": "Connect Secure", "kev": {"dateAdded": "2026-01-01"}}
        with tempfile.TemporaryDirectory() as d:
            meta = build_products(recs, Path(d), "2026-11-26T00:00:00Z")
            m = json.loads((Path(d) / "m.json").read_text())["vendors"]
            self.assertEqual(m["microsoft"], {"n": 4, "products": [["exchange_server", 4]]})
            self.assertFalse((Path(d) / "t.json").exists())          # 1 CVE, not KEV: dropped
            self.assertIn("ivanti", json.loads((Path(d) / "i.json").read_text())["vendors"])
            self.assertEqual(meta["vendors"], 2)


if __name__ == "__main__":
    unittest.main()
