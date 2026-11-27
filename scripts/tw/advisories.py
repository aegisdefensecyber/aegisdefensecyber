"""Vendor security advisories: CVEs vendors publish, often before NVD / the CVE List have a record.

Sources (all machine-readable; nothing is scraped from free-form web pages):
  * CSAF 2.0 providers — every provider listed by the BSI and CERT@VDE CSAF aggregators and the GCVE
    registry, plus major vendors discovered through security.txt or /.well-known/csaf/.
    Read through ROLIE feeds or directory changes.csv, newest first, incrementally.
  * GitHub Security Advisories (reviewed) — open-source packages.
  * Vendor feeds for vendors without CSAF: Fortinet PSIRT RSS, Palo Alto Networks advisory JSON.

Output (threatwatch/data/advisories/index.json): {cve: [advisory summary]} for advisories released or
updated in the last RETAIN_DAYS, each with vendor, title, link, severity, affected products, fixes and
any exploitation statement the vendor made. Collection state lives in advisories/state.json.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any

from .common import USER_AGENT, safe_url

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
RETAIN_DAYS = 90
FIRST_LOOKBACK_DAYS = 90
PER_PROVIDER = int(os.environ.get("TW_ADV_PER_PROVIDER") or 80)
TIME_BUDGET = float(os.environ.get("TW_ADV_BUDGET_S") or 480)

AGGREGATORS = [
    "https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json",          # BSI
    "https://aggregator.certvde.com/.well-known/csaf-aggregator/aggregator.json",    # CERT@VDE
]
GCVE_REGISTRY = "https://www.gcve.eu/dist/gcve.json"
KNOWN_PROVIDERS = [
    "https://msrc.microsoft.com/csaf/provider-metadata.json",
    "https://www.cisco.com/.well-known/csaf/provider-metadata.json",
    "https://security.access.redhat.com/data/csaf/v2/provider-metadata.json",
    "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json",
    "https://www.suse.com/.well-known/csaf/provider-metadata.json",
]
# Major vendors probed for CSAF via security.txt / well-known locations (cached for a week)
DISCOVER_DOMAINS = [
    "oracle.com", "sap.com", "broadcom.com", "vmware.com", "paloaltonetworks.com", "fortinet.com",
    "juniper.net", "ivanti.com", "citrix.com", "cloud.com", "f5.com", "hpe.com", "dell.com", "ibm.com",
    "intel.com", "nvidia.com", "adobe.com", "sonicwall.com", "zyxel.com", "atlassian.com", "checkpoint.com",
    "sophos.com", "trendmicro.com", "solarwinds.com", "progress.com", "veeam.com", "netapp.com", "hitachi.com",
    "rockwellautomation.com", "honeywell.com", "phoenixcontact.com", "bosch.com", "mitsubishielectric.com",
    "lenovo.com", "hp.com", "apple.com", "google.com", "mozilla.org", "canonical.com", "debian.org",
]
ORACLE_RSS = "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml"
FORTINET_RSS = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
PANW_JSON = "https://security.paloaltonetworks.com/json/?limit=100&sort=-date"
GHSA_API = "https://api.github.com/advisories?type=reviewed&sort=updated&direction=desc&per_page=100"


# ----------------------------------------------------------------------------- http
def _get(url: str, timeout: int = 25, accept: str = "application/json", headers: dict | None = None) -> tuple[bytes, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(40 * 1024 * 1024), dict(r.headers)


def _json(url: str, **kw) -> Any:
    return json.loads(_get(url, **kw)[0])


def _ts(s: Any) -> datetime | None:
    if not s:
        return None
    s = str(s).strip()
    for fmt in (None, "%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z"):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00")) if fmt is None else datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _iso(d: datetime | None) -> str | None:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def _clip(s: Any, n: int) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _sev(score: Any) -> str | None:
    try:
        x = float(score)
    except (TypeError, ValueError):
        return None
    return "CRITICAL" if x >= 9 else "HIGH" if x >= 7 else "MEDIUM" if x >= 4 else "LOW" if x > 0 else None


# ----------------------------------------------------------------------------- CSAF parsing
def _product_names(tree: Any) -> dict[str, str]:
    names: dict[str, str] = {}

    def walk(b):
        if isinstance(b, dict):
            p = b.get("product")
            if isinstance(p, dict) and p.get("product_id"):
                names[p["product_id"]] = p.get("name") or p["product_id"]
            for k in ("branches", "full_product_names", "relationships"):
                v = b.get(k)
                if isinstance(v, list):
                    for x in v:
                        if k == "full_product_names" and isinstance(x, dict) and x.get("product_id"):
                            names[x["product_id"]] = x.get("name") or x["product_id"]
                        elif k == "relationships" and isinstance(x, dict):
                            fp = x.get("full_product_name") or {}
                            if fp.get("product_id"):
                                names[fp["product_id"]] = fp.get("name") or fp["product_id"]
                        else:
                            walk(x)
        elif isinstance(b, list):
            for x in b:
                walk(x)
    walk(tree or {})
    return names


def _vendor_of(tree: Any) -> str | None:
    for b in (tree or {}).get("branches") or []:
        if b.get("category") == "vendor":
            return b.get("name")
    return None


def parse_csaf(doc: Any, url: str | None = None) -> list[dict]:
    """One summary per CVE in a CSAF 2.0 document."""
    if not isinstance(doc, dict) or not isinstance(doc.get("document"), dict):
        return []
    d = doc["document"]
    tlp = ((d.get("distribution") or {}).get("tlp") or {}).get("label")
    if tlp and str(tlp).upper() not in ("WHITE", "CLEAR"):
        return []
    tr = d.get("tracking") or {}
    pub = (d.get("publisher") or {}).get("name")
    names = _product_names(doc.get("product_tree"))
    vendor = _vendor_of(doc.get("product_tree")) or pub
    self_url = next((safe_url(r.get("url")) for r in d.get("references") or []
                     if r.get("category") == "self" and not str(r.get("url", "")).lower().endswith(".json")), None)
    link = self_url or safe_url(url)
    out = []
    for v in doc.get("vulnerabilities") or []:
        cve = v.get("cve")
        if not cve or not CVE_RE.fullmatch(str(cve)):
            continue
        score = None
        for s in v.get("scores") or []:
            for k in ("cvss_v4", "cvss_v3", "cvss_v2"):
                if isinstance(s.get(k), dict) and s[k].get("baseScore") is not None:
                    score = s[k]["baseScore"] if score is None else max(score, s[k]["baseScore"])
        st = v.get("product_status") or {}
        aff_ids = (st.get("known_affected") or []) + (st.get("first_affected") or []) + (st.get("last_affected") or [])
        products = []
        for pid in aff_ids:
            n = names.get(pid, pid)
            if n not in products:
                products.append(n)
        fixes = []
        for r in v.get("remediations") or []:
            cat = r.get("category")
            if cat not in ("vendor_fix", "mitigation", "workaround", "none_available", "no_fix_planned"):
                continue
            item = {"type": cat, "text": _clip(r.get("details"), 240), "url": safe_url(r.get("url"))}
            if item not in fixes:
                fixes.append(item)
        exploited, note = None, None
        for t in v.get("threats") or []:
            if t.get("category") == "exploit_status":
                note = _clip(t.get("details"), 200)
                low = note.lower()
                exploited = True if re.search(r"exploited\s*:\s*yes|actively exploited|exploited in the wild", low) else \
                    False if re.search(r"exploited\s*:\s*no", low) else exploited
        desc = next((n.get("text") for n in v.get("notes") or [] if n.get("category") in ("description", "summary")), None)
        out.append({
            "cve": cve, "source": "CSAF", "vendor": _clip(vendor, 80) or None, "publisher": _clip(pub, 80) or None,
            "id": _clip(tr.get("id"), 80), "title": _clip(v.get("title") or d.get("title"), 200),
            "url": link, "csaf": safe_url(url),
            "released": _iso(_ts(tr.get("initial_release_date"))), "updated": _iso(_ts(tr.get("current_release_date"))),
            "cvss": score, "severity": _sev(score) or (_clip(((d.get("aggregate_severity") or {}).get("text")), 20).upper() or None),
            "products": [_clip(p, 120) for p in products[:8]], "productsMore": max(0, len(products) - 8),
            "fixes": fixes[:6], "exploited": exploited, "exploitNote": note,
            "description": _clip(desc, 600) or None,
            "cwe": ((v.get("cwe") or {}).get("id")) if isinstance(v.get("cwe"), dict) else None,
        })
    return out


# ----------------------------------------------------------------------------- CSAF discovery & fetching
def _metadata_from_security_txt(domain: str) -> str | None:
    for u in (f"https://{domain}/.well-known/security.txt", f"https://www.{domain}/.well-known/security.txt"):
        try:
            txt = _get(u, timeout=12, accept="text/plain")[0].decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
        for line in txt.splitlines():
            if line.lower().startswith("csaf:"):
                cand = safe_url(line.split(":", 1)[1].strip())
                if cand:
                    return cand
    return None


def discover(domain: str) -> str | None:
    cands = [_metadata_from_security_txt(domain), f"https://{domain}/.well-known/csaf/provider-metadata.json",
             f"https://www.{domain}/.well-known/csaf/provider-metadata.json", f"https://csaf.data.security.{domain}/provider-metadata.json"]
    for u in [c for c in cands if c]:
        try:
            pm = _json(u, timeout=12)
            if isinstance(pm, dict) and (pm.get("distributions") or pm.get("publisher")):
                return u
        except Exception:  # noqa: BLE001
            continue
    return None


def provider_list(state: dict, notes: list[str]) -> list[str]:
    urls = list(KNOWN_PROVIDERS)
    for agg in AGGREGATORS:
        try:
            a = _json(agg)
            for p in (a.get("csaf_providers") or []) + (a.get("csaf_publishers") or []):
                u = safe_url((p.get("metadata") or {}).get("url"))
                if u:
                    urls.append(u)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"aggregator {agg.split('/')[2]} unavailable ({_clip(exc, 80)})")
    try:
        reg = _json(GCVE_REGISTRY)
        for x in reg if isinstance(reg, list) else reg.get("entries", []):
            for k in ("gcve_api", "gcve_dump"):
                u = safe_url(x.get(k))
                if u and u.endswith("provider-metadata.json"):
                    urls.append(u)
    except Exception as exc:  # noqa: BLE001
        notes.append(f"GCVE registry unavailable ({_clip(exc, 80)})")
    disc = state.setdefault("discovered", {})
    now = time.time()
    todo = [d for d in DISCOVER_DOMAINS if now - (disc.get(d) or {}).get("checked", 0) > 7 * 86400]
    with ThreadPoolExecutor(8) as ex:
        futs = {ex.submit(discover, d): d for d in todo}
        for f in as_completed(futs):
            try:
                disc[futs[f]] = {"url": f.result(), "checked": now}
            except Exception:  # noqa: BLE001
                disc[futs[f]] = {"url": None, "checked": now}
    urls += [v["url"] for v in disc.values() if v.get("url")]
    seen, out = set(), []
    for u in urls:
        k = u.lower().rstrip("/")
        if k not in seen:
            seen.add(k)
            out.append(u)
    return out


def _entries(pm_url: str, since: datetime) -> tuple[str, list[tuple[str, datetime]]]:
    """(publisher name, [(document url, updated)]) newer than `since`, newest first."""
    pm = _json(pm_url)
    pub = (pm.get("publisher") or {}).get("name") or pm_url.split("/")[2]
    found: list[tuple[str, datetime]] = []
    for dist in pm.get("distributions") or []:
        rolie = (dist.get("rolie") or {}).get("feeds") or []
        for feed in rolie:
            if str(feed.get("tlp_label", "WHITE")).upper() not in ("WHITE", "CLEAR"):
                continue
            fu = safe_url(feed.get("url"))
            if not fu or "/vex" in fu.lower():
                continue
            f = _json(fu, timeout=40)
            for e in ((f.get("feed") or {}).get("entry") or []):
                upd = _ts(e.get("updated") or e.get("published"))
                href = safe_url((e.get("content") or {}).get("src")) or next(
                    (safe_url(l.get("href")) for l in e.get("link") or [] if l.get("rel") == "self"), None)
                if href and upd and upd > since:
                    found.append((href, upd))
        du = safe_url(dist.get("directory_url"))
        if du and "/vex" not in du.lower():
            base = du if du.endswith("/") else du + "/"
            raw = _get(base + "changes.csv", timeout=40, accept="text/csv")[0].decode("utf-8", "replace")
            for row in csv.reader(io.StringIO(raw)):
                if len(row) >= 2:
                    upd = _ts(row[1])
                    if upd and upd > since and row[0].endswith(".json"):
                        found.append((urllib.parse.urljoin(base, row[0]), upd))
    found.sort(key=lambda x: x[1], reverse=True)
    dedup, seen = [], set()
    for u, t in found:
        if u not in seen:
            seen.add(u)
            dedup.append((u, t))
    return pub, dedup


def collect_csaf(state: dict, deadline: float, notes: list[str]) -> tuple[list[dict], dict]:
    provs = provider_list(state, notes)
    cursors = state.setdefault("cursors", {})
    default_since = datetime.now(timezone.utc) - timedelta(days=FIRST_LOOKBACK_DAYS)
    out: list[dict] = []
    meta = {"providers": len(provs), "providersOk": 0, "documents": 0, "failed": []}

    def one(pm_url):
        since = _ts(cursors.get(pm_url)) or default_since
        pub, ents = _entries(pm_url, since)
        ents = ents[:PER_PROVIDER]
        rows, newest = [], since
        for u, t in ents:
            if time.time() > deadline:
                break
            try:
                rows += parse_csaf(_json(u, timeout=30), u)
                newest = max(newest, t)
            except Exception:  # noqa: BLE001 — skip a bad document
                continue
        return pm_url, pub, rows, newest, len(ents)

    with ThreadPoolExecutor(8) as ex:
        futs = [ex.submit(one, u) for u in provs]
        for f in as_completed(futs):
            try:
                pm_url, pub, rows, newest, n = f.result()
                cursors[pm_url] = _iso(newest)
                out += rows
                meta["providersOk"] += 1
                meta["documents"] += n
            except Exception as exc:  # noqa: BLE001
                meta["failed"].append(_clip(str(exc), 100))
    meta["failed"] = meta["failed"][:10]
    return out, meta


# ----------------------------------------------------------------------------- GitHub Security Advisories
def parse_ghsa(a: dict) -> dict | None:
    cve = a.get("cve_id")
    if not cve or not CVE_RE.fullmatch(str(cve)):
        return None
    cv = a.get("cvss") or {}
    score = cv.get("score")
    for k in ("cvss_v4", "cvss_v3"):
        s = ((a.get("cvss_severities") or {}).get(k) or {}).get("score")
        if s:
            score = max(score or 0, s)
    prods, fixes = [], []
    for v in a.get("vulnerabilities") or []:
        pk = v.get("package") or {}
        name = f"{pk.get('ecosystem', '')}: {pk.get('name', '')}".strip(": ")
        rng = v.get("vulnerable_version_range")
        prods.append(_clip(f"{name} {rng or ''}", 120))
        fp = v.get("first_patched_version")
        fp = fp.get("identifier") if isinstance(fp, dict) else fp
        fixes.append({"type": "vendor_fix" if fp else "none_available",
                      "text": _clip(f"Upgrade {name} to {fp} or later" if fp else f"No patched version of {name} listed yet", 240),
                      "url": safe_url(a.get("html_url"))})
    return {"cve": cve, "source": "GitHub", "vendor": "Open source (GitHub Advisory Database)", "publisher": "GitHub",
            "id": a.get("ghsa_id"), "title": _clip(a.get("summary"), 200), "url": safe_url(a.get("html_url")), "csaf": None,
            "released": _iso(_ts(a.get("published_at"))), "updated": _iso(_ts(a.get("updated_at"))),
            "cvss": score, "severity": (a.get("severity") or "").upper() or _sev(score),
            "products": prods[:8], "productsMore": max(0, len(prods) - 8), "fixes": fixes[:6],
            "exploited": None, "exploitNote": None, "description": _clip(a.get("description"), 600) or None,
            "cwe": ((a.get("cwes") or [{}])[0] or {}).get("cwe_id")}


def collect_ghsa(state: dict, deadline: float) -> tuple[list[dict], dict]:
    tok = (os.environ.get("GITHUB_TOKEN") or "").strip()
    hdr = {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {tok}"} if tok else {})}
    since = _ts(state.get("ghsaCursor")) or datetime.now(timezone.utc) - timedelta(days=FIRST_LOOKBACK_DAYS)
    url, out, newest, pages = GHSA_API, [], since, 0
    while url and pages < 15 and time.time() < deadline:
        body, h = _get(url, headers=hdr)
        items = json.loads(body)
        pages += 1
        stop = False
        for a in items:
            upd = _ts(a.get("updated_at"))
            if upd and upd <= since:
                stop = True
                break
            r = parse_ghsa(a)
            if r:
                out.append(r)
            if upd:
                newest = max(newest, upd)
        m = re.search(r'<([^>]+)>;\s*rel="next"', h.get("Link") or h.get("link") or "")
        url = None if stop else (m.group(1) if m else None)
    state["ghsaCursor"] = _iso(newest)
    return out, {"pages": pages, "advisories": len(out), "authenticated": bool(tok)}


# ----------------------------------------------------------------------------- vendor feeds (no CSAF)
def parse_fortinet_rss(xml: str) -> list[dict]:
    out = []
    for item in re.findall(r"<item>(.*?)</item>", xml or "", re.S):
        g = lambda tag: (re.search(rf"<{tag}>(.*?)</{tag}>", item, re.S) or [None, ""])[1]  # noqa: E731
        desc = re.sub(r"<[^>]+>", " ", g("description").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"))
        link = safe_url(g("link").strip())
        title = _clip(re.sub(r"<!\[CDATA\[|\]\]>", "", g("title")), 200)
        sm = re.search(r"CVSSv3 Score:\s*([\d.]+)", desc)
        score = float(sm.group(1)) if sm else None
        for cve in sorted(set(CVE_RE.findall(desc))):
            out.append({"cve": cve, "source": "Vendor feed", "vendor": "Fortinet", "publisher": "Fortinet PSIRT",
                        "id": link.rsplit("/", 1)[-1] if link else None, "title": title, "url": link, "csaf": None,
                        "released": _iso(_ts(g("pubDate").strip())), "updated": _iso(_ts(g("pubDate").strip())),
                        "cvss": score, "severity": _sev(score), "products": [], "productsMore": 0,
                        "fixes": [{"type": "vendor_fix", "text": "See the Solutions section of the Fortinet advisory for fixed versions.", "url": link}],
                        "exploited": True if re.search(r"exploited in the wild|observed .* exploited", desc, re.I) else None,
                        "exploitNote": None, "description": _clip(desc, 600) or None, "cwe": None})
    return out


def parse_vendor_rss(xml: str, vendor: str) -> list[dict]:
    """Generic vendor bulletin RSS (e.g. Oracle CPU / Security Alerts). Items without CVEs are kept (cve=None)."""
    out = []
    for item in re.findall(r"<item>(.*?)</item>", xml or "", re.S):
        g = lambda tag: (re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", item, re.S) or [None, ""])[1]  # noqa: E731
        clean = lambda t: re.sub(r"<!\[CDATA\[|\]\]>", "", t).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")  # noqa: E731
        desc = re.sub(r"<[^>]+>", " ", clean(g("description")))
        link = safe_url(clean(g("link")).strip())
        title = _clip(clean(g("title")), 200)
        when = _iso(_ts(clean(g("pubDate")).strip()))
        base = {"source": "Vendor feed", "vendor": vendor, "publisher": vendor, "id": (link or title or "")[-120:], "title": title,
                "url": link, "csaf": None, "released": when, "updated": when, "cvss": None, "severity": None, "products": [],
                "productsMore": 0, "fixes": [{"type": "vendor_fix", "text": "See the vendor advisory for patches.", "url": link}] if link else [],
                "exploited": None, "exploitNote": None, "description": _clip(desc, 600) or None, "cwe": None}
        cves = sorted(set(CVE_RE.findall(title + " " + desc)))
        out += [dict(base, cve=c) for c in cves] or [dict(base, cve=None)]
    return out


def parse_panw(items: Any) -> list[dict]:
    out = []
    for a in items if isinstance(items, list) else []:
        ids = set(CVE_RE.findall(str(a.get("ID") or ""))) | set(CVE_RE.findall(json.dumps(a.get("CVE") or a.get("cves") or "")))
        if not ids:
            continue
        sol = " ".join(x.get("value", "") for x in a.get("solution") or [] if isinstance(x, dict))
        prob = " ".join(x.get("value", "") for x in a.get("problem") or [] if isinstance(x, dict))
        expl = " ".join(x.get("value", "") for x in a.get("exploit") or [] if isinstance(x, dict))
        aid = str(a.get("ID") or "")
        url = safe_url(f"https://security.paloaltonetworks.com/{urllib.parse.quote(aid)}") if aid else None
        for cve in sorted(ids):
            out.append({"cve": cve, "source": "Vendor feed", "vendor": "Palo Alto Networks", "publisher": "Palo Alto Networks PSIRT",
                        "id": aid, "title": _clip(a.get("title"), 200), "url": url, "csaf": None,
                        "released": _iso(_ts(a.get("date"))), "updated": _iso(_ts(a.get("updated") or a.get("date"))),
                        "cvss": a.get("baseScore") or None, "severity": (a.get("baseSeverity") or "").upper() or None,
                        "products": [_clip(p, 120) for p in (a.get("product") or [])][:8], "productsMore": 0,
                        "fixes": [{"type": "vendor_fix", "text": _clip(sol, 240), "url": url}] if sol else [],
                        "exploited": True if re.search(r"aware of (?:limited )?(?:malicious )?exploitation|actively exploited", expl, re.I)
                        else False if re.search(r"not aware of any malicious exploitation", expl, re.I) else None,
                        "exploitNote": _clip(expl, 200) or None, "description": _clip(prob, 600) or None, "cwe": None})
    return out


# ----------------------------------------------------------------------------- orchestration
def collect(prev: dict, state: dict, now: datetime) -> tuple[dict, dict]:
    """Returns (index document, updated state). Keeps previous entries when a source fails."""
    deadline = time.time() + TIME_BUDGET
    notes: list[str] = []
    rows: list[dict] = []
    meta: dict[str, Any] = {}
    for name, fn in (("csaf", lambda: collect_csaf(state, deadline, notes)),
                     ("github", lambda: collect_ghsa(state, deadline))):
        try:
            r, m = fn()
            rows += r
            meta[name] = {"ok": True, **m}
        except Exception as exc:  # noqa: BLE001
            meta[name] = {"ok": False, "error": _clip(exc, 160)}
    try:
        rows += parse_fortinet_rss(_get(FORTINET_RSS, accept="application/rss+xml")[0].decode("utf-8", "replace"))
        meta["fortinet"] = {"ok": True}
    except Exception as exc:  # noqa: BLE001
        meta["fortinet"] = {"ok": False, "error": _clip(exc, 160)}
    try:
        rows += parse_panw(_json(PANW_JSON))
        meta["paloalto"] = {"ok": True}
    except Exception as exc:  # noqa: BLE001
        meta["paloalto"] = {"ok": False, "error": _clip(exc, 160)}

    cves: dict[str, list[dict]] = {k: list(v) for k, v in ((prev or {}).get("cves") or {}).items()}
    for r in rows:
        lst = cves.setdefault(r["cve"], [])
        key = (r["source"], r["vendor"], r["id"])
        lst[:] = [x for x in lst if (x.get("source"), x.get("vendor"), x.get("id")) != key] + [{k: v for k, v in r.items() if k != "cve"}]
    cutoff = now - timedelta(days=RETAIN_DAYS)
    for c in list(cves):
        cves[c] = sorted((x for x in cves[c] if (_ts(x.get("updated") or x.get("released")) or now) >= cutoff),
                         key=lambda x: x.get("updated") or "", reverse=True)[:6]
        if not cves[c]:
            del cves[c]
    doc = {"schemaVersion": 1, "generatedAt": _iso(now), "retainDays": RETAIN_DAYS, "sources": meta,
           "notes": notes[:10], "count": len(cves), "cves": dict(sorted(cves.items()))}
    return doc, state
