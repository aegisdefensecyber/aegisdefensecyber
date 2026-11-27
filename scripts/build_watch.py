#!/usr/bin/env python3
"""Watchlist alerts (Layer 1): what changed for every watched technology category since the last run.

Runs before the daily brief (so the brief includes it) and after each catalog build (so alerts are
immediate). Watches come from threatwatch/data/watch/watchlist.json (the Consolidated Vendor Watchlist).

Levels
  critical  added to CISA KEV · new exploitation evidence (CISA, VulnCheck, CERT, vendor statement)
  high      first public exploit/PoC for a critical or exploited CVE · EPSS enters the top 10% ·
            exploited or KEV-linked vendor advisory · urgent campaign alert (CISA, Talos, Unit 42, …)
  medium    new critical (CVSS 9+) CVEs · new or revised high/critical vendor or CERT advisories
Critical and high are "significant": they go to alert subscribers and trigger the analyst briefing.

Outputs (threatwatch/data/watch/): alerts.json (60 days), latest.json (this run), summary.json
(per-watch status for the brief), alerts.xml + feeds/<watch>.xml (RSS), state.json (small sets).
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tw.advrepo import Repo  # noqa: E402
from tw.common import DATA_DIR, read_json, write_json  # noqa: E402

W = DATA_DIR / "watch"
CVES = DATA_DIR / "cves"
SITE = "https://aegisdefensecyber.com/threatwatch/"
KEEP_DAYS = 60
LEVEL_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}
# national CERTs that re-publish vendor advisories in French, German or Dutch: shown only in the CERT watches
REPUBLISHERS = {"certfr_avis", "certfr_alerte", "csaf_certbund", "csaf_ncscnl"}
NOT_ADVISORY = ("osv_", "pysec", "bitnami", "debian_tracker", "cleanstart", "moksha", "cvelistv5", "github", "gna-", "variot", "avid")


def iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def spaced(s) -> str:
    return " " + " ".join(re.sub(r"[^a-z0-9.+]+", " ", str(s or "").lower()).split()) + " "


def compact(s) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(s or "").lower())


class Matcher:
    """Whole-word match on names; compact names also match ('checkpoint' = 'Check Point')."""
    def __init__(self, terms):
        self.terms = [(spaced(t), compact(t)) for t in terms if str(t).strip()]

    def hit(self, text) -> bool:
        if not self.terms or not text:
            return False
        s, c = spaced(text), compact(text)
        return any(ts in s or c == tc or (len(tc) >= 6 and c.startswith(tc)) for ts, tc in self.terms)


def compile_watch(w: dict) -> dict:
    return {**w, "_v": Matcher(w.get("vendors") or []), "_p": Matcher(w.get("products") or []),
            "_k": Matcher(w.get("keywords") or []), "_cves": set(w.get("cves") or []),
            "_srcs": set(w.get("advisorySources") or []), "_x": Matcher(w.get("exclude") or [])}


def cve_hits(w: dict, row: dict) -> bool:
    if row["cve"] in w["_cves"]:
        return True
    if w["_x"].hit(row.get("product")) or w["_x"].hit(row.get("vendor")):
        return False
    return w["_v"].hit(row.get("vendor")) or w["_p"].hit(row.get("product"))


def adv_significant(a: dict, kev_ids: set[str], minimum: str = "high") -> bool:
    if a.get("expl") or set(a.get("cves") or []) & kev_ids:
        return True
    if minimum == "critical":
        return a.get("sev") == "CRITICAL" or (a.get("cvss") or 0) >= 9
    return a.get("sev") in ("CRITICAL", "HIGH") or (a.get("cvss") or 0) >= 7


def adv_hits(w: dict, a: dict) -> bool:
    if a["src"] in w["_srcs"]:
        return True
    if a["src"] in REPUBLISHERS or a["src"].startswith(NOT_ADVISORY):
        return False
    if set(a.get("cves") or []) & w["_cves"]:
        return True
    title = a.get("title") or ""
    if w["_x"].hit(title) or any(w["_x"].hit(p) for p in a.get("products") or []):
        return False
    return w["_v"].hit(a.get("vendor")) or w["_k"].hit(title) or (
        w["_p"].hit(title) or any(w["_p"].hit(p) for p in a.get("products") or []))


def record(cid: str) -> dict:
    p = CVES / cid.split("-")[1] / f"{cid}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def label(row: dict) -> str:
    vp = " ".join(x for x in [row.get("vendor"), (row.get("product") or "").split(" (+")[0]] if x)
    return f"{row['cve']} ({vp})" if vp else row["cve"]


def ev(w, level, kind, key, title, detail, plain, now, cves=(), links=()) -> dict:
    eid = hashlib.sha1(f"{w['id']}|{kind}|{key}|{now.date()}".encode()).hexdigest()[:12]
    return {"id": eid, "watch": w["id"], "watchName": w["name"], "section": w.get("section"), "ts": iso(now),
            "level": level, "kind": kind, "title": title, "detail": detail, "plain": plain,
            "cves": list(cves)[:25], "links": [l for l in links if l.get("u")][:6]}


def run(now: datetime) -> dict:
    wl = read_json(W / "watchlist.json", {}) or {}
    watches = [compile_watch(w) for w in wl.get("watches") or []]
    state = read_json(W / "state.json", {}) or {}
    since = datetime.fromisoformat(state["lastRun"].replace("Z", "+00:00")) if state.get("lastRun") else now - timedelta(hours=24)
    since_day = since.strftime("%Y-%m-%d")
    first_run = "lastRun" not in state
    idx = read_json(CVES / "index.json", {}) or {}
    F = idx.get("fields") or []
    rows = [dict(zip(F, x)) for x in idx.get("items") or []]
    epss = (read_json(CVES / "epss.json", {}) or {}).get("scores") or {}
    advs = Repo(DATA_DIR / "advisories").recent(now, 10)
    kev_ids = {r["cve"] for r in rows if r.get("kev")}
    cvelink = lambda c: {"t": c, "u": f"{SITE}validate.html?cve={c}"}  # noqa: E731

    # ---- CVE-level signals (shared by all watches)
    by_watch: dict[str, list[dict]] = {w["id"]: [] for w in watches}
    for r in rows:
        for w in watches:
            if w.get("allKev"):
                if r.get("kev"):
                    by_watch[w["id"]].append(r)
            elif cve_hits(w, r):
                by_watch[w["id"]].append(r)
    watched = {r["cve"]: r for lst in by_watch.values() for r in lst}

    prev_itw = state.get("itw") or {}
    prev_poc = set(state.get("poc") or [])
    prev_epss = set(state.get("epss90") or [])
    itw_now, poc_now, epss_now, kev_new, expl_new = {}, set(), set(), {}, {}
    for cid, r in watched.items():
        crit = (r.get("cvss") or 0) >= 9 or r.get("kev") or r.get("itw") or r.get("zeroDay")
        if r.get("kev") or r.get("itw"):
            rec = record(cid)
            ex = rec.get("exploitation") or {}
            srcs = sorted({s.get("source") for s in ex.get("sources") or [] if s.get("source")})
            itw_now[cid] = ";".join(srcs)
            added = (rec.get("kev") or {}).get("dateAdded") or ""
            if r.get("kev") and added >= since_day and "CISA KEV" not in (prev_itw.get(cid) or ""):
                kev_new[cid] = rec
            new_src = set(srcs) - set((prev_itw.get(cid) or "").split(";")) - {"CISA KEV", ""}
            if new_src and not first_run:
                expl_new[cid] = sorted(new_src)
        if crit and r.get("poc"):
            poc_now.add(cid)
        e = epss.get(cid)
        if e and e[1] is not None and e[1] >= 0.9 and (r.get("cvss") or 0) >= 7:
            epss_now.add(cid)

    events: list[dict] = []
    for w in watches:
        mine = {r["cve"]: r for r in by_watch[w["id"]]}
        for cid in sorted(set(kev_new) & set(mine)):
            r, rec = mine[cid], kev_new[cid]
            due = (rec.get("kev") or {}).get("dueDate")
            events.append(ev(w, "critical", "kev_added", cid, f"{label(r)} added to CISA Known Exploited Vulnerabilities",
                             f"CISA confirmed active exploitation on {(rec.get('kev') or {}).get('dateAdded')}" + (f"; federal remediation due {due}." if due else "."),
                             f"Attackers are actively using this flaw. If your organization runs {r.get('vendor') or 'this product'}, patch or mitigate it now.",
                             now, [cid], [cvelink(cid), {"t": "CISA KEV", "u": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}]))
        for cid in sorted(set(expl_new) & set(mine) - set(kev_new)):
            r = mine[cid]
            events.append(ev(w, "critical", "exploitation", cid, f"New exploitation evidence for {label(r)}",
                             "Reported by: " + ", ".join(expl_new[cid]) + ". Reports are evidence, not proof that a specific system was compromised.",
                             f"Security researchers or authorities now report attacks using this flaw. Confirm whether you run {r.get('vendor') or 'the product'} and prioritise the fix.",
                             now, [cid], [cvelink(cid)]))
        if not first_run:
            for cid in sorted((poc_now - prev_poc) & set(mine)):
                r = mine[cid]
                events.append(ev(w, "high", "poc_first", cid, f"Public exploit code now available for {label(r)}",
                                 "A public proof-of-concept or exploit reference was listed for this critical or exploited CVE. PoC repositories are unvetted.",
                                 "Public attack code lowers the bar for attackers. Expect exploitation attempts to rise; patch ahead of them.",
                                 now, [cid], [cvelink(cid)]))
            for cid in sorted((epss_now - prev_epss) & set(mine)):
                r, e = mine[cid], epss.get(cid)
                events.append(ev(w, "high", "epss_jump", cid, f"Exploitation likelihood jumped for {label(r)}",
                                 f"EPSS {e[0]:.1%} (top {max(1, round((1 - e[1]) * 100))}% of all CVEs).",
                                 "Forecasting models now rate this flaw among the most likely to be exploited in the next 30 days.",
                                 now, [cid], [cvelink(cid)]))
        new_crit = sorted((r for r in mine.values() if (r.get("published") or "") >= since_day
                           and ((r.get("cvss") or 0) >= 9 or r.get("kev"))), key=lambda r: -(r.get("cvss") or 0))
        if new_crit and not w.get("allKev"):
            events.append(ev(w, "high" if any(r.get("kev") or r.get("itw") for r in new_crit) else "medium", "new_critical",
                             ",".join(r["cve"] for r in new_crit[:10]),
                             f"{len(new_crit)} new critical CVE{'s' if len(new_crit) != 1 else ''} in {w['name']}",
                             "; ".join(f"{label(r)} CVSS {r.get('cvss')}" for r in new_crit[:6]) + ("…" if len(new_crit) > 6 else ""),
                             "Newly published critical flaws in technology in this category. Check whether you run the named products and plan updates.",
                             now, [r["cve"] for r in new_crit], [cvelink(r["cve"]) for r in new_crit[:4]]))
        # ---- advisories
        for a in advs:
            if not adv_hits(w, a):
                continue
            recent_rel = (a.get("released") or a.get("updated") or "")[:10] >= (since - timedelta(days=3)).strftime("%Y-%m-%d")
            is_new = (a.get("seen") or "") >= since_day and recent_rel          # backfilled old advisories are not news
            is_rev = not is_new and (a.get("updated") or "")[:19] > iso(since)[:19] and (a.get("released") or "")[:10] < (a.get("updated") or "")[:10]
            if not (is_new or is_rev):
                continue
            urgent = w["id"] == "campaigns-urgent" and a["src"] in w["_srcs"] and (
                a["src"] in ("cisa_advisories", "certfr_alerte")
                or re.search(r"zero[- ]?day|0-day|actively exploit|in the wild|exploitation|ransomware|campaign|emergency", a.get("title") or "", re.I))
            if w["id"] == "campaigns-urgent" and not urgent:
                continue
            if not (urgent or adv_significant(a, kev_ids, w.get("advisoryMin") or "high")):
                continue
            hot = urgent or a.get("expl") or bool(set(a.get("cves") or []) & kev_ids)
            level = "high" if hot and is_new and (urgent or a["src"] not in REPUBLISHERS) else "medium"
            events.append(ev(w, level, "advisory_new" if is_new else "advisory_revised", f"{a['src']}|{a['id']}",
                             ("Urgent alert: " if urgent else "New advisory: " if is_new else "Advisory revised: ") + (a.get("title") or a["id"]),
                             f"{a.get('vendor') or a['src']} · {a['id']}" + (f" · {len(a.get('cves') or [])} CVE(s)" if a.get("cves") else " · no CVE assigned")
                             + (" · exploitation reported" if a.get("expl") else "") + (f" · severity {a['sev'].title()}" if a.get("sev") else ""),
                             ("A government or vendor security team issued an urgent warning. Read it and confirm whether it applies to you."
                              if urgent else "The vendor published a security advisory rated high or critical. Confirm whether you use the affected products and apply the fix."
                              if is_new else "The vendor changed an advisory (affected versions, fixes or exploitation status may have changed). Re-check exposure."),
                             now, a.get("cves") or [], [{"t": a["id"], "u": a.get("url")}]))

    # ---- write
    old = read_json(W / "alerts.json", {}) or {}
    have = {e["id"] for e in old.get("events") or []}
    events = [e for e in events if e["id"] not in have]                 # same alert already raised today
    cutoff = iso(now - timedelta(days=KEEP_DAYS))
    hist = events + [e for e in old.get("events") or [] if e["ts"] >= cutoff]
    hist.sort(key=lambda e: (e["ts"], -LEVEL_RANK[e["level"]]), reverse=True)
    hist = hist[:3000]
    day_ago = iso(now - timedelta(hours=24))
    summary = []
    for w in watches:
        recent = [e for e in hist if e["watch"] == w["id"] and e["ts"] >= day_ago]
        n = {l: sum(1 for e in recent if e["level"] == l) for l in LEVEL_RANK}
        status = "red" if n["critical"] else "amber" if n["high"] else "watch" if n["medium"] else "green"
        top = sorted(recent, key=lambda e: LEVEL_RANK[e["level"]])[:3]
        summary.append({"id": w["id"], "name": w["name"], "section": w.get("section"), "tier": w.get("tier"), "status": status,
                        "counts": n, "cves": len(by_watch[w["id"]]), "headline": top[0]["title"] if top else None,
                        "plain": top[0]["plain"] if top else None, "top": [{"title": e["title"], "level": e["level"], "id": e["id"]} for e in top]})
    meta = {"schemaVersion": 2, "generatedAt": iso(now), "window": {"since": iso(since), "until": iso(now)},
            "watches": [{"id": w["id"], "name": w["name"], "section": w.get("section"), "tier": w.get("tier"), "cves": len(by_watch[w["id"]])}
                        for w in watches]}
    write_json(W / "alerts.json", {**meta, "events": hist})
    write_json(W / "latest.json", {**meta, "count": len(events), "events": events})
    write_json(W / "summary.json", {**meta, "summary": summary})
    (W / "state.json").write_text(json.dumps({"lastRun": iso(now), "itw": itw_now, "poc": sorted(poc_now), "epss90": sorted(epss_now)},
                                             separators=(",", ":"), sort_keys=True), encoding="utf-8")
    write_rss(W / "alerts.xml", "All significant watchlist alerts", [e for e in hist if e["level"] in ("critical", "high")][:80], now, "alerts.html")
    (W / "feeds").mkdir(exist_ok=True)
    for w in watches:
        write_rss(W / "feeds" / f"{w['id']}.xml", w["name"], [e for e in hist if e["watch"] == w["id"]][:50], now, f"alerts.html#watch={w['id']}")
    return {"events": len(events), "levels": {l: sum(1 for e in events if e["level"] == l) for l in LEVEL_RANK}}


def write_rss(path: Path, title: str, events: list[dict], now: datetime, page: str) -> None:
    items = []
    for e in events:
        link = next((l["u"] for l in e.get("links") or [] if l.get("u")), SITE + "alerts.html")
        items.append(f"<item><title>{escape('[' + e['level'].upper() + '] ' + e['watchName'] + ': ' + e['title'])}</title>"
                     f"<link>{escape(link)}</link><guid isPermaLink=\"false\">aegis-watch-{e['id']}</guid>"
                     f"<pubDate>{datetime.fromisoformat(e['ts'].replace('Z', '+00:00')).strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate>"
                     f"<description>{escape(e['detail'] + ' — ' + (e.get('plain') or ''))}</description></item>")
    xml = (f'<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel><title>AEGIS ThreatWatch — {escape(title)}</title>'
           f"<link>{SITE}{escape(page)}</link><description>Significant changes for watched technology, from AEGIS ThreatWatch.</description>"
           f"<lastBuildDate>{now.strftime('%a, %d %b %Y %H:%M:%S +0000')}</lastBuildDate>" + "".join(items) + "</channel></rss>\n")
    path.write_text(xml, encoding="utf-8")


if __name__ == "__main__":
    out = run(datetime.now(timezone.utc))
    print(f"Watch alerts: {out['events']} new events {out['levels']}")
