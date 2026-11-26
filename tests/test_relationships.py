"""Threat Map graph built from a tiny ATT&CK-shaped bundle."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tw.relationships import build_graph  # noqa: E402
from tw.validate import validate_relationships  # noqa: E402


def ref(eid, kind):
    return [{"source_name": "mitre-attack", "external_id": eid, "url": f"https://attack.mitre.org/{kind}/{eid}"}]


BUNDLE = {"objects": [
    {"type": "campaign", "id": "campaign--1", "name": "Test Campaign", "external_references": ref("C9999", "campaigns"),
     "description": "Actors exploited CVE-2099-0001 in edge devices.", "first_seen": "2025-01-01T00:00:00Z",
     "last_seen": "2025-06-01T00:00:00Z", "modified": "2026-04-01T00:00:00Z"},
    {"type": "campaign", "id": "campaign--2", "name": "No CVE Campaign", "external_references": ref("C9998", "campaigns"),
     "description": "Nothing here.", "modified": "2026-04-01T00:00:00Z"},
    {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Test Group", "aliases": ["Test Group", "TG"],
     "external_references": ref("G9999", "groups")},
    {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Exploit Public-Facing Application",
     "external_references": ref("T1190", "techniques")},
    {"type": "attack-pattern", "id": "attack-pattern--2", "name": "Phishing", "external_references": ref("T1566", "techniques")},
    {"type": "relationship", "id": "relationship--1", "relationship_type": "attributed-to", "source_ref": "campaign--1",
     "target_ref": "intrusion-set--1", "modified": "2026-04-02T00:00:00Z",
     "external_references": [{"source_name": "Vendor 2025", "url": "https://example.com/report"}]},
    {"type": "relationship", "id": "relationship--2", "relationship_type": "uses", "source_ref": "campaign--1",
     "target_ref": "attack-pattern--1", "modified": "2026-04-02T00:00:00Z"},
    {"type": "relationship", "id": "relationship--3", "relationship_type": "uses", "source_ref": "campaign--1",
     "target_ref": "attack-pattern--2", "modified": "2026-04-02T00:00:00Z"},
]}


class GraphTests(unittest.TestCase):
    def test_graph(self):
        g = build_graph(BUNDLE, {"CVE-2099-0001": {"product": "Example Gateway", "kev": True, "cvss": 9.8}}, "20.1",
                        "2026-11-23T00:00:00Z")
        self.assertEqual(validate_relationships(g), [])
        self.assertEqual(g["dataset"]["status"], "verified")
        labels = {n["label"] for n in g["nodes"]}
        self.assertIn("Test Group", labels)
        self.assertNotIn("No CVE Campaign", labels)                 # campaigns without a named CVE are skipped
        self.assertNotIn("T1566 Phishing", labels)                  # only exploitation techniques
        rel = {(e["relation"], e["evidence"]["url"]) for e in g["edges"]}
        self.assertIn(("attributed", "https://example.com/report"), rel)      # cites the report when ATT&CK has one
        self.assertIn(("exploits", "https://attack.mitre.org/campaigns/C9999"), rel)
        cve = next(n for n in g["nodes"] if n["type"] == "cve")
        self.assertTrue(cve["kev"])


if __name__ == "__main__":
    unittest.main()


class IocAndIndustryTests(unittest.TestCase):
    def test_stix_parsing_and_defang(self):
        import sys as _s
        from pathlib import Path as _P
        _s.path.insert(0, str(_P(__file__).resolve().parents[1] / "scripts"))
        from tw.iocs import stix_iocs, advisory_codes
        from tw.relationships import defang, sectors
        doc = {"objects": [
            {"type": "indicator", "pattern": "[domain-name:value = 'evil.example']", "valid_from": "2024-02-01T00:00:00Z"},
            {"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.7']"},
            {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"},
            {"type": "indicator", "pattern": "[domain-name:value = '<script>']"},
            {"type": "malware", "pattern": "[domain-name:value = 'skip.example']"}]}
        got = stix_iocs(doc, 10)
        self.assertEqual([g["type"] for g in got], ["domain", "ipv4", "sha256"])
        self.assertEqual(got[0]["seen"], "2024-02-01")
        self.assertEqual(defang("url", "http://evil.example/x"), "hxxp://evil[.]example/x")
        self.assertEqual(advisory_codes({"external_references": [
            {"url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"}]}), {"aa23-320a"})
        self.assertEqual(sectors("it was used"), [])
        self.assertIn("Technology & IT", sectors("targeted IT providers"))
        self.assertIn("Government", sectors("against government ministries (Citation: X)"))

    def test_add_iocs_validates(self):
        import sys as _s
        from pathlib import Path as _P
        _s.path.insert(0, str(_P(__file__).resolve().parents[1] / "scripts"))
        from tw.relationships import add_iocs
        from tw.validate import validate_relationships
        g = {"schemaVersion": 1, "dataset": {"status": "verified"},
             "nodes": [{"id": "a-G1", "type": "actor", "label": "APTX"}, {"id": "k-C1", "type": "campaign", "label": "C1"}],
             "edges": []}
        n = add_iocs(g, {"k-C1": {"aa24-001a"}},
                     {"aa24-001a": [{"type": "domain", "value": "bad.example", "seen": "2024-01-01", "source": "CISA advisory",
                                     "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-001a", "ref": "AA24-001A"}]},
                     {"APTX": [{"type": "ipv4", "value": "192.0.2.1", "seen": "2026-10-01", "confidenceLevel": 90,
                                "source": "abuse.ch ThreatFox", "ref": "ThreatFox #9", "url": "https://threatfox.abuse.ch/ioc/9/"}]},
                     "2026-11-25T00:00:00Z")
        self.assertEqual(n, 2)
        self.assertEqual(validate_relationships(g), [])
        labels = sorted(x["label"] for x in g["nodes"] if x["type"] == "ioc")
        self.assertEqual(labels, ["192[.]0[.]2[.]1", "bad[.]example"])
        self.assertTrue(all(e["relation"] == "indicator" and e["evidence"]["url"].startswith("https://") for e in g["edges"]))


class Stix1XmlTest(unittest.TestCase):
    def test_reads_cybox_values(self):
        from tw.iocs import stix1_iocs
        x = ('<AddressObj:Address_Value condition="Equals">185.10.20.30##comma##not-an-ip</AddressObj:Address_Value>'
             '<cyboxCommon:Simple_Hash_Value>' + "b" * 64 + '</cyboxCommon:Simple_Hash_Value>'
             '<DomainNameObj:Value>bad.example.com</DomainNameObj:Value>')
        got = {(i["type"], i["value"]) for i in stix1_iocs(x, 10)}
        self.assertEqual(got, {("ipv4", "185.10.20.30"), ("sha256", "b" * 64), ("domain", "bad.example.com")})


class CveIndexTest(unittest.TestCase):
    def test_group_and_malware_mentions(self):
        from tw.relationships import build_cve_index
        ref = lambda i, u: {"external_references": [{"source_name": "mitre-attack", "external_id": i, "url": u}]}
        b = {"objects": [
            {"id": "intrusion-set--1", "type": "intrusion-set", "name": "APTX", "aliases": ["APTX", "Ghost"], **ref("G9999", "https://attack.mitre.org/groups/G9999")},
            {"id": "malware--1", "type": "malware", "name": "BadRAT", **ref("S9999", "https://attack.mitre.org/software/S9999")},
            {"id": "attack-pattern--1", "type": "attack-pattern", "name": "Exploit Public-Facing Application", **ref("T1190", "https://attack.mitre.org/techniques/T1190")},
            {"id": "relationship--1", "type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--1",
             "target_ref": "attack-pattern--1", "description": "APTX exploited CVE-2024-1111 on edge devices.(Citation: X)"},
            {"id": "relationship--2", "type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "malware--1"},
            {"id": "relationship--3", "type": "relationship", "relationship_type": "uses", "source_ref": "malware--1",
             "target_ref": "attack-pattern--1", "description": "BadRAT can exploit CVE-2023-2222."},
        ]}
        x = build_cve_index(b, "2026-11-26T00:00:00Z")["cves"]
        a = x["CVE-2024-1111"][0]
        self.assertEqual((a["name"], a["confidence"], a["technique"]["id"], a["via"]), ("APTX", "high", "T1190", None))
        self.assertNotIn("Citation", a["why"])
        m = x["CVE-2023-2222"][0]
        self.assertEqual((m["name"], m["confidence"], m["via"]), ("APTX", "moderate", "BadRAT"))
