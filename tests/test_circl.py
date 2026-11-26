import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tw.advrepo import Repo  # noqa: E402
from tw.circl import normalize  # noqa: E402

CERTFR = {"$ref": "https://www.cert.ssi.gouv.fr/openapi.json", "reference": "CERTFR-2026-ALE-017",
          "title": "Multiples vulnérabilités dans F5 NGINX", "initial_release_date": "2026-11-18T00:00:00",
          "last_revision_date": "2026-11-19T00:00:00",
          "affected_systems": [{"description": "x", "product": {"name": "NGINX Plus", "vendor": {"name": "F5"}}}],
          "cves": [{"name": "CVE-2026-123007"}, {"name": "CVE-2026-123633"}],
          "vendor_advisories": [{"title": "Bulletin F5 K000163928", "url": "https://my.f5.com/manage/s/article/K000163928"}]}
OSV_GH = {"schema_version": "1.4.0", "id": "GHSA-3w92-wmmc-hm3c", "modified": "2026-11-25T21:30:41Z", "published": "2026-11-25T21:30:41Z",
          "aliases": ["CVE-2026-81336"], "details": "GitLab issue", "affected": [], "references": [],
          "database_specific": {"severity": "MODERATE", "github_reviewed": False}}
UBUNTU = {"schema_version": "1.9.2", "id": "UBUNTU-CVE-2026-135745", "details": "FFmpeg bug", "aliases": [], "upstream": ["CVE-2026-135745"],
          "severity": [{"type": "Ubuntu", "score": "medium"}], "published": "2026-11-24T04:17:00Z", "modified": "2026-11-25T17:45:55Z",
          "affected": [{"package": {"ecosystem": "Ubuntu:Pro:14.04:LTS", "name": "libav"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "6:9.21"}]}]}]}
JVN = {"title": "GENAI Web vulnerable to SSRF", "link": "https://jvndb.jvn.jp/en/contents/2026/JVNDB-2026-000178.html",
       "description": "… CVE-2026-131916", "sec:identifier": "JVNDB-2026-000178", "sec:cpe": {"@vendor": "Digital Agency", "@product": "GENAI Web"},
       "sec:cvss": {"@score": "4.1", "@severity": "Medium"}, "dcterms:issued": "2026-11-25T13:36+09:00", "dcterms:modified": "2026-11-25T13:36+09:00"}
CVE5 = {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": "CVE-2026-133203", "state": "PUBLISHED", "datePublished": "2026-11-26T04:04:09.089Z",
        "dateUpdated": "2026-11-26T04:04:09.089Z"}, "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Revive Adserver flaw"}],
        "affected": [{"vendor": "Revive", "product": "Adserver"}], "metrics": [{"cvssV3_0": {"baseScore": 5.3}}]}}}
DEB = {"id": "DEBIAN-TEMP-1155011-C8D858", "issue": "TEMP-1155011-C8D858", "modified": "2026-11-26T04:26:36.568640+00:00",
       "packages": {"roundcube": {"releases": {"trixie": {"fixed_version": "1.6.22+dfsg-0+deb13u1"}}}}}


class NormalizeTest(unittest.TestCase):
    def test_certfr_alert_multi_cve(self):
        r = normalize(CERTFR, "certfr_alerte")
        self.assertEqual((r["id"], r["vendor"], r["expl"], r["lang"]), ("CERTFR-2026-ALE-017", "F5", True, "fr"))
        self.assertEqual(r["cves"], ["CVE-2026-123007", "CVE-2026-123633"])
        self.assertEqual(r["url"], "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-017/")
        self.assertEqual(r["fix"][0]["u"], "https://my.f5.com/manage/s/article/K000163928")

    def test_osv_github_and_ubuntu(self):
        g = normalize(OSV_GH, "github")
        self.assertEqual((g["url"], g["sev"], g["reviewed"]), ("https://github.com/advisories/GHSA-3w92-wmmc-hm3c", "MEDIUM", False))
        u = normalize(UBUNTU, "osv_ubuntu")
        self.assertEqual((u["cves"], u["sev"], u["products"]), (["CVE-2026-135745"], "MEDIUM", ["Ubuntu: libav"]))
        self.assertIn("6:9.21", u["fix"][0]["t"])

    def test_jvn_cve5_debian(self):
        j = normalize(JVN, "jvndb")
        self.assertEqual((j["id"], j["cvss"], j["cves"], j["released"]), ("JVNDB-2026-000178", 4.1, ["CVE-2026-131916"], "2026-11-25T04:36:00Z"))
        c = normalize(CVE5, "cvelistv5")
        self.assertEqual((c["id"], c["vendor"], c["cvss"], c["sev"]), ("CVE-2026-133203", "Revive", 5.3, "MEDIUM"))
        d = normalize(DEB, "debian_tracker")
        self.assertEqual((d["cves"], d["vendor"]), ([], "Debian"))       # TEMP issue: advisory with no CVE yet, kept


class RepoTest(unittest.TestCase):
    def test_upsert_keeps_seen_and_drops_cve_mirrors(self):
        now = "2026-11-26T05:00:00Z"
        with tempfile.TemporaryDirectory() as d:
            repo = Repo(Path(d))
            a = normalize(CERTFR, "certfr_alerte")
            repo.upsert([a, normalize(OSV_GH, "github")], now)       # unreviewed GHSA without packages: not stored
            repo.flush(now)
            self.assertEqual((repo.added, repo.changed), (1, 0))
            repo2 = Repo(Path(d))
            repo2.upsert([dict(a, title="Updated title")], "2026-11-27T05:00:00Z")
            repo2.flush("2026-11-27T05:00:00Z")
            items = repo2.recent(datetime(2026, 11, 27, tzinfo=timezone.utc), 30)
            self.assertEqual(len(items), 1)
            self.assertEqual((items[0]["title"], items[0]["seen"]), ("Updated title", "2026-11-26"))
            self.assertEqual(repo2.changed, 1)


if __name__ == "__main__":
    unittest.main()
