"""CIRCL Vulnerability-Lookup: multi-source advisory collection (https://vulnerability.circl.lu).

Follows CIRCL's API policy: incremental sync with `since=` on /api/vulnerability/, a descriptive
User-Agent, and no more than 20 requests per minute (anonymous limit; Retry-After honoured on 429).
Each source keeps its own cursor (since-date + page), so a large first backfill resumes across runs.

Every record is reduced to one compact advisory summary (normalize()). Formats handled: OSV (GitHub
reviewed + unreviewed, Ubuntu, Debian, PyPI, Go, Android, Bitnami, Drupal…), CSAF 2.0 (Microsoft,
Cisco, Red Hat, SUSE, Siemens, CISA, CERT-Bund, NCSC-NL and many ICS vendors), CERT-FR, JVN iPedia,
CVE JSON 5 (the CVE List), the Debian security tracker, RSS-style bulletins and AVID; anything else
falls back to a generic reader.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from .common import safe_url

API = "https://vulnerability.circl.lu/api"
UA = "AegisThreatWatch/1.0 (+https://aegisdefensecyber.com/threatwatch/; advisory sync)"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
MIN_INTERVAL = 3.2                     # 20 requests/minute anonymous limit, with headroom
EXCLUDE = {"ossf_malicious_packages", "cnvd", "fstec", "gsd", "nvd", "fkie_nvd", "alpine", "cisa_known_exploited"}
HEAVY = {"csaf_opensuse", "csaf_suse", "csaf_redhat", "csaf_microsoft", "osv_ubuntu", "osv_azurelinux", "osv_openeuler",
         "osv_bellsoft", "osv_homebrew", "osv_root", "cleanstart", "osv_almalinux", "osv_rocky", "osv_debian_elts", "osv_dhi"}
PRIORITY = ["certfr_alerte", "certfr_avis", "jvndb", "csaf_", "drupal", "tailscale", "gna-", "avid", "variot",
            "cvelistv5", "github", "debian_tracker", "osv_", "pysec", "bitnami_vulndb", "cleanstart", "moksha"]
MAX_PAGES = int(os.environ.get("TW_CIRCL_MAX_PAGES") or 12)   # per source per run: every source progresses each run
GROUPS = [("csaf_", "Vendor & CERT CSAF"), ("certfr", "National CERT"), ("jvndb", "National CERT"),
          ("github", "Open source"), ("osv_", "Distro & package"), ("pysec", "Distro & package"),
          ("bitnami", "Distro & package"), ("debian", "Distro & package"), ("cleanstart", "Distro & package"),
          ("drupal", "Vendor"), ("tailscale", "Vendor"), ("cvelistv5", "CVE List"), ("gna-", "GCVE authority"),
          ("avid", "AI systems"), ("variot", "IoT")]
LABEL = {"certfr_avis": "CERT-FR advisories", "certfr_alerte": "CERT-FR alerts", "jvndb": "JVN iPedia (Japan)",
         "github": "GitHub Advisory Database", "cvelistv5": "CVE List (CVE Program)", "debian_tracker": "Debian security tracker",
         "pysec": "PyPI advisories", "bitnami_vulndb": "Bitnami", "csaf_certbund": "CERT-Bund (Germany)",
         "csaf_ncscnl": "NCSC-NL (Netherlands)", "csaf_cisa": "CISA ICS advisories", "variot": "VARIoT", "avid": "AVID (AI)",
         "drupal": "Drupal", "tailscale": "Tailscale"}


def group_of(src: str) -> str:
    return next((g for p, g in GROUPS if src.startswith(p)), "Other")


def label_of(src: str) -> str:
    if src in LABEL:
        return LABEL[src]
    if src.startswith("csaf_"):
        return src[5:].replace("_", " ").title() + " (CSAF)"
    if src.startswith("osv_"):
        return src[4:].replace("_", " ").title() + " (OSV)"
    return src.replace("_", " ").title()


# ----------------------------------------------------------------------------- helpers
def _clip(s: Any, n: int) -> str:
    s = re.sub(r"<[^>]+>", " ", str(s or ""))
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _date(s: Any) -> str | None:
    if not s:
        return None
    s = str(s).strip()
    for fmt in (None, "%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M%z"):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00")) if fmt is None else datetime.strptime(s, fmt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    m = re.match(r"(\d{4}-\d{2}-\d{2})", s)
    return m.group(1) + "T00:00:00Z" if m else None


def _sev(x: Any) -> str | None:
    s = str(x or "").strip().upper()
    s = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH", "HOCH": "HIGH", "MITTEL": "MEDIUM", "NIEDRIG": "LOW",
         "KRITISCH": "CRITICAL", "NEGLIGIBLE": "LOW"}.get(s, s)
    return s if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else None


def _sev_of_score(v: Any) -> str | None:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return "CRITICAL" if x >= 9 else "HIGH" if x >= 7 else "MEDIUM" if x >= 4 else "LOW" if x > 0 else None


def _cves(*objs: Any) -> list[str]:
    found: list[str] = []
    for o in objs:
        for c in CVE_RE.findall(o if isinstance(o, str) else json.dumps(o or "", ensure_ascii=False)):
            if c not in found:
                found.append(c)
    return found[:60]


def _rec(src: str, **kw) -> dict:
    r = {"id": None, "src": src, "vendor": None, "title": None, "url": None, "released": None, "updated": None,
         "cves": [], "sev": None, "cvss": None, "products": [], "fix": [], "expl": None, "lang": None}
    r.update({k: v for k, v in kw.items() if v not in (None, "", [])})
    r["products"] = [_clip(p, 100) for p in r["products"] if p][:6]
    r["fix"] = [f for f in r["fix"] if f.get("t") or f.get("u")][:3]
    r["title"] = _clip(r["title"], 220) or r["id"]
    r["updated"] = r["updated"] or r["released"]
    return r


# ----------------------------------------------------------------------------- normalizers
def from_osv(d: dict, src: str) -> dict:
    ds = d.get("database_specific") or {}
    sev = _sev(ds.get("severity"))
    for s in d.get("severity") or []:
        if not sev and s.get("type") not in ("CVSS_V2", "CVSS_V3", "CVSS_V4"):
            sev = _sev(s.get("score"))
    prods, fixes = [], []
    for a in d.get("affected") or []:
        pk = a.get("package") or {}
        name = pk.get("name")
        if name:
            eco = str(pk.get("ecosystem") or "").split(":")[0]
            prods.append(f"{eco}: {name}" if eco else name)
        for rg in a.get("ranges") or []:
            for ev in rg.get("events") or []:
                if ev.get("fixed") and len(fixes) < 3:
                    fixes.append({"t": f"Fixed in {name} {ev['fixed']}" if name else f"Fixed in {ev['fixed']}", "u": None})
    refs = d.get("references") or []
    url = next((safe_url(r.get("url")) for r in refs if r.get("type") == "ADVISORY" and "nvd.nist.gov" not in str(r.get("url"))), None) \
        or next((safe_url(r.get("url")) for r in refs if r.get("type") in ("ADVISORY", "WEB")), None)
    if src == "github" and str(d.get("id", "")).startswith("GHSA-"):
        url = f"https://github.com/advisories/{d['id']}"
    vendor = {"github": "Open source (GitHub)", "debian_tracker": "Debian", "pysec": "PyPI", "drupal": "Drupal",
              "bitnami_vulndb": "Bitnami"}.get(src) or (src[4:].replace("_", " ").title() if src.startswith("osv_") else None)
    reviewed = ds.get("github_reviewed")
    return _rec(src, id=d.get("id"), vendor=vendor, title=d.get("summary") or d.get("details"), url=url,
                released=_date(d.get("published")), updated=_date(d.get("modified")),
                cves=_cves(d.get("id"), d.get("aliases"), d.get("upstream")), sev=sev, products=sorted(set(prods)),
                fix=fixes, reviewed=reviewed if src == "github" else None)


def from_csaf(d: dict, src: str) -> dict:
    doc = d.get("document") or {}
    tr = doc.get("tracking") or {}
    pub = doc.get("publisher") or {}
    vend = next((b.get("name") for b in ((d.get("product_tree") or {}).get("branches") or []) if b.get("category") == "vendor"), None)
    refs = doc.get("references") or []
    url = next((safe_url(r.get("url")) for r in refs if r.get("category") == "self" and not str(r.get("url", "")).lower().endswith(".json")), None) \
        or next((safe_url(r.get("url")) for r in refs if r.get("category") == "self"), None) \
        or next((safe_url(r.get("url")) for r in refs), None)
    best, fixes, expl = None, [], None
    for v in d.get("vulnerabilities") or []:
        for s in v.get("scores") or []:
            for k in ("cvss_v4", "cvss_v3", "cvss_v2"):
                bs = (s.get(k) or {}).get("baseScore") if isinstance(s.get(k), dict) else None
                if bs is not None:
                    best = bs if best is None else max(best, bs)
        for r in v.get("remediations") or []:
            if r.get("category") in ("vendor_fix", "mitigation", "workaround") and len(fixes) < 3:
                f = {"t": _clip(r.get("details"), 160), "u": safe_url(r.get("url"))}
                if f not in fixes:
                    fixes.append(f)
        for t in v.get("threats") or []:
            if t.get("category") == "exploit_status" and re.search(r"exploited\s*:\s*yes|actively exploited", str(t.get("details")), re.I):
                expl = True
    names = []

    def walk(b):
        for x in b or []:
            if isinstance(x, dict):
                if x.get("category") in ("product_name", "product_family") and x.get("name"):
                    names.append(x["name"])
                walk(x.get("branches"))
    walk((d.get("product_tree") or {}).get("branches"))
    agg = _sev((doc.get("aggregate_severity") or {}).get("text"))
    return _rec(src, id=tr.get("id"), vendor=vend or pub.get("name"), title=doc.get("title"), url=url,
                released=_date(tr.get("initial_release_date")), updated=_date(tr.get("current_release_date")),
                cves=_cves([v.get("cve") for v in d.get("vulnerabilities") or []]), cvss=best,
                sev=_sev_of_score(best) or agg, products=list(dict.fromkeys(names)), fix=fixes, expl=expl,
                lang=(doc.get("lang") or "")[:2] or None, publisher=pub.get("name"))


def from_certfr(d: dict, src: str) -> dict:
    ref = d.get("reference") or ""
    kind = "alerte" if "-ALE-" in ref else "avis"
    prods, vendor = [], None
    for a in d.get("affected_systems") or []:
        p = a.get("product") or {}
        vendor = vendor or (p.get("vendor") or {}).get("name")
        if p.get("name"):
            prods.append(((p.get("vendor") or {}).get("name", "") + " " + p["name"]).strip())
    fixes = [{"t": _clip(v.get("title"), 160), "u": safe_url(v.get("url"))} for v in d.get("vendor_advisories") or []]
    return _rec(src, id=ref, vendor=vendor, title=d.get("title"), lang="fr",
                url=f"https://www.cert.ssi.gouv.fr/{kind}/{ref}/" if ref else None,
                released=_date(d.get("initial_release_date")), updated=_date(d.get("last_revision_date")),
                cves=_cves([c.get("name") for c in d.get("cves") or []]), products=list(dict.fromkeys(prods)),
                fix=fixes, expl=True if kind == "alerte" else None)


def from_jvn(d: dict, src: str) -> dict:
    cpe = d.get("sec:cpe") or {}
    cpe = cpe[0] if isinstance(cpe, list) and cpe else cpe
    cv = d.get("sec:cvss") or {}
    cv = cv[0] if isinstance(cv, list) and cv else cv
    score = cv.get("@score") if isinstance(cv, dict) else None
    return _rec(src, id=d.get("sec:identifier"), vendor=(cpe or {}).get("@vendor"), title=d.get("title"),
                url=safe_url(d.get("link")), released=_date(d.get("dcterms:issued")),
                updated=_date(d.get("dcterms:modified")), cves=_cves(d.get("sec:references"), d.get("description")),
                cvss=float(score) if score else None, sev=_sev((cv or {}).get("@severity")) or _sev_of_score(score),
                products=[(cpe or {}).get("@product")])


def from_cve5(d: dict, src: str) -> dict:
    meta = d.get("cveMetadata") or {}
    cna = (d.get("containers") or {}).get("cna") or {}
    desc = next((x.get("value") for x in cna.get("descriptions") or [] if str(x.get("lang", "")).startswith("en")), None)
    aff = [a for a in cna.get("affected") or [] if a.get("vendor") and a.get("vendor") != "n/a"]
    best = None
    for c in [cna] + list((d.get("containers") or {}).get("adp") or []):
        for m in c.get("metrics") or []:
            for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if isinstance(m.get(k), dict) and m[k].get("baseScore") is not None:
                    best = m[k]["baseScore"] if best is None else max(best, m[k]["baseScore"])
    cid = meta.get("cveId")
    return _rec(src, id=cid, vendor=aff[0]["vendor"] if aff else None, title=cna.get("title") or desc,
                url=f"https://www.cve.org/CVERecord?id={cid}" if cid else None,
                released=_date(meta.get("datePublished")), updated=_date(meta.get("dateUpdated")),
                cves=[cid] if cid else [], cvss=best, sev=_sev_of_score(best),
                products=[f"{a['vendor']} {a.get('product', '')}".strip() for a in aff], state=meta.get("state"))


def from_debian(d: dict, src: str) -> dict:
    issue = d.get("issue") or d.get("id")
    prods, fixes = [], []
    for pkg, info in (d.get("packages") or {}).items():
        prods.append(pkg)
        for rel, r in ((info or {}).get("releases") or {}).items():
            if r.get("fixed_version") and len(fixes) < 3:
                fixes.append({"t": f"{pkg} fixed in {rel} {r['fixed_version']}", "u": None})
    return _rec(src, id=d.get("id"), vendor="Debian", title=f"{issue}: {', '.join(prods[:3])}",
                url=f"https://security-tracker.debian.org/tracker/{urllib.parse.quote(str(issue))}" if issue else None,
                released=_date(d.get("modified")), updated=_date(d.get("modified")),
                cves=_cves(issue), products=prods, fix=fixes)


def from_feed(d: dict, src: str) -> dict:
    return _rec(src, id=d.get("id") or d.get("link"), vendor=label_of(src), title=d.get("title"),
                url=safe_url(d.get("link")), released=_date(d.get("published")), updated=_date(d.get("updated") or d.get("published")),
                cves=_cves(d.get("title"), d.get("summary")))


def from_avid(d: dict, src: str) -> dict:
    aff = d.get("affects") or {}
    return _rec(src, id=(d.get("metadata") or {}).get("vuln_id"), vendor=", ".join(aff.get("developer") or [])[:80] or None,
                title=((d.get("problemtype") or {}).get("description") or {}).get("value"),
                url=next((safe_url(r.get("url")) for r in d.get("references") or []), None),
                released=_date(d.get("published_date")), updated=_date(d.get("last_modified_date")),
                products=[a.get("name") for a in aff.get("artifacts") or []], cves=_cves(d.get("references")))


def from_generic(d: dict, src: str) -> dict:
    g = lambda *ks: next((d.get(k) for k in ks if d.get(k)), None)  # noqa: E731
    return _rec(src, id=g("id", "reference", "identifier", "name"), title=g("title", "summary", "name", "description"),
                url=safe_url(g("url", "link", "html_url")), released=_date(g("published", "published_at", "date", "created")),
                updated=_date(g("modified", "updated", "updated_at", "last_modified")), cves=_cves(d), vendor=label_of(src))


def normalize(d: Any, src: str) -> dict | None:
    if not isinstance(d, dict):
        return None
    try:
        if src == "cvelistv5" or "cveMetadata" in d:
            r = from_cve5(d, src)
        elif isinstance(d.get("document"), dict) and "tracking" in d["document"]:
            r = from_csaf(d, src)
        elif src.startswith("certfr") or "affected_systems" in d:
            r = from_certfr(d, src)
        elif src == "jvndb" or "sec:identifier" in d:
            r = from_jvn(d, src)
        elif src == "debian_tracker" or ("packages" in d and "issue" in d):
            r = from_debian(d, src)
        elif d.get("data_type") == "AVID":
            r = from_avid(d, src)
        elif "schema_version" in d or "aliases" in d or ("affected" in d and "id" in d):
            r = from_osv(d, src)
        elif "title_detail" in d or "summary_detail" in d:
            r = from_feed(d, src)
        else:
            r = from_generic(d, src)
    except Exception:  # noqa: BLE001 — never let one odd record stop a source
        r = from_generic(d, src)
    if not r.get("id"):
        return None
    r["id"] = _clip(r["id"], 120)
    return r


# ----------------------------------------------------------------------------- HTTP with the CIRCL rate limit
class Client:
    def __init__(self, deadline: float):
        self.deadline, self.last, self.calls = deadline, 0.0, 0
        key = (os.environ.get("CIRCL_API_KEY") or "").strip()
        self.headers = {"User-Agent": UA, "Accept": "application/json", **({"X-API-KEY": key} if key else {})}
        self.interval = 1.6 if key else MIN_INTERVAL

    def get(self, path: str) -> Any:
        for attempt in range(3):
            wait = self.interval - (time.time() - self.last)
            if wait > 0:
                time.sleep(wait)
            if time.time() > self.deadline:
                raise TimeoutError("time budget reached")
            self.last = time.time()
            self.calls += 1
            try:
                req = urllib.request.Request(API + path, headers=self.headers)
                with urllib.request.urlopen(req, timeout=90) as r:
                    return json.loads(r.read(120 * 1024 * 1024))
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    time.sleep(min(90, int(e.headers.get("Retry-After") or 30)))
                    continue
                if e.code >= 500 and attempt < 2:
                    time.sleep(10)
                    continue
                raise
        raise RuntimeError("CIRCL kept rate-limiting")


def sources(client: Client) -> list[str]:
    d = client.get("/stats/vulnerability/sources")
    names = [s.get("source") for s in (d.get("sources") or []) if s.get("source")]
    keep = [s for s in names if s not in EXCLUDE]
    rank = lambda s: next((i for i, p in enumerate(PRIORITY) if s == p or (p.endswith(("_", "-")) and s.startswith(p))), len(PRIORITY))  # noqa: E731
    return sorted(keep, key=lambda s: (s in HEAVY, rank(s), s))


def collect(state: dict, now: datetime, budget_s: float, backfill_days: int = 90,
            on_records=None) -> dict:
    """Pull every configured source incrementally. Calls on_records(src, [records]) per page.
    Returns per-source health. `state` (cursors) is updated in place."""
    client = Client(time.time() + budget_s)
    health: dict[str, dict] = {}
    cur = state.setdefault("circl", {})
    try:
        srcs = sources(client)
    except Exception as exc:  # noqa: BLE001
        return {"_circl": {"ok": False, "error": _clip(exc, 200)}}
    today = now.strftime("%Y-%m-%d")
    for src in srcs:
        st = cur.setdefault(src, {})
        h = health.setdefault(src, {"label": label_of(src), "group": group_of(src), "records": 0, "pages": 0})
        if "since" not in st:
            days = 14 if src == "cvelistv5" else backfill_days
            st.update({"since": (now - timedelta(days=days)).strftime("%Y-%m-%d"), "page": 1, "passStart": today})
        per = 50 if src.startswith("csaf_") else 100
        pages_now = 0
        try:
            while True:
                if pages_now >= MAX_PAGES:
                    h.update({"complete": False, "note": f"backfill in progress (page {st['page']}); continues next run"})
                    break
                pages_now += 1
                q = urllib.parse.urlencode({"source": src, "since": st["since"], "page": st["page"], "per_page": per,
                                            "date_sort": "updated", "sort_order": "asc"})
                items = client.get(f"/vulnerability/?{q}")
                items = items if isinstance(items, list) else (items.get("data") or items.get("results") or []) if isinstance(items, dict) else []
                recs = [r for r in (normalize(x, src) for x in items) if r]
                if on_records and recs:
                    on_records(src, recs)
                h["records"] += len(recs)
                h["pages"] += 1
                if len(items) < per:                      # pass complete: next run starts from this pass's start date
                    yday = (datetime.strptime(st.get("passStart", today), "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%d")
                    st.update({"since": yday, "page": 1, "passStart": today, "lastComplete": now.strftime("%Y-%m-%dT%H:%M:%SZ")})
                    h["complete"] = True
                    break
                st["page"] += 1
            h["ok"] = True
        except TimeoutError:
            h.update({"ok": True, "complete": False, "note": "time budget reached; resumes next run"})
            break
        except Exception as exc:  # noqa: BLE001
            h.update({"ok": False, "error": _clip(exc, 200)})
    for src in srcs:                                     # sources not reached this run
        health.setdefault(src, {"label": label_of(src), "group": group_of(src), "records": 0, "pages": 0,
                                "ok": True, "complete": False, "note": "not reached this run (time budget)"})
    health["_circl"] = {"ok": True, "calls": client.calls, "sources": len(srcs)}
    return health
