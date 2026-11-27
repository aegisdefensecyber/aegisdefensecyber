#!/usr/bin/env python3
"""Watchlist alerts (Layer 1): detect what changed for watched vendors, products and CVEs.

Runs after each catalog build. Compares the current CVE catalog and advisory repository with the
snapshot from the previous run (threatwatch/data/watch/state.json) and records events:

  critical  added to CISA KEV · new exploitation evidence (KEV, VulnCheck, CERT alert, vendor statement)
  high      first public PoC / exploit · EPSS jumps into the top 10% · new vendor advisory naming a focus CVE
  medium    new CVEs for the watch (one summary per run) · new or revised vendor advisories · CVSS changed

Outputs: threatwatch/data/watch/alerts.json (60 days of events), latest.json (this run),
alerts.xml (RSS) — read by threatwatch/alerts.html and by the daily briefing task (Layer 2).
The first run only records a baseline.
"""
from __future__ import annotations

import hashlib
import json
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


def iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def low(s) -> str:
    return str(s or "").lower()


def matches_cve(w: dict, row: dict) -> bool:
    if row["cve"] in w.get("cves", []):
        return True
    v, p = low(row.get("vendor")), low(row.get("product"))
    return any(x in v for x in map(low, w.get("vendors", []))) or any(x in p for x in map(low, w.get("products", [])))


def matches_adv(w: dict, a: dict, watched: set[str]) -> bool:
    hay = " ".join([low(a.get("vendor")), low(a.get("title"))] + [low(p) for p in a.get("products") or []])
    if any(c in set(w.get("cves", [])) for c in a.get("cves") or []):
        return True
    if any(low(k) in hay for k in w.get("keywords", [])):
        return True
    if any(x in low(a.get("vendor")) for x in map(low, w.get("vendors", []))):
        return True
    return any(x in " ".join(low(p) for p in a.get("products") or []) for x in map(low, w.get("products", []))) \
        and bool(set(a.get("cves") or []) & watched)


def cve_signals(cid: str, epss: dict) -> dict | None:
    p = CVES / cid.split("-")[1] / f"{cid}.json"
    if not p.exists():
        return None
    r = json.loads(p.read_text(encoding="utf-8"))
    ex = r.get("exploitation") or {}
    e = epss.get(cid) or [None, None]
    return {"kev": bool((r.get("kev") or {}).get("dateAdded")), "itw": bool(ex.get("inTheWild")),
            "srcs": sorted({s.get("source") for s in ex.get("sources") or [] if s.get("source")}),
            "poc": int((r.get("pocs") or {}).get("count") or 0),
            "epss": round(e[0], 3) if e[0] is not None else None, "pct": round(e[1], 2) if e[1] is not None else None,
            "cvss": (r.get("cvss") or {}).get("score"), "vendor": r.get("vendor"), "product": r.get("product"),
            "title": (r.get("title") or r.get("description") or "")[:160]}


def ev(watch: dict, level: str, kind: str, title: str, detail: str, now: datetime, cves=(), links=()) -> dict:
    eid = hashlib.sha1(f"{watch['id']}|{kind}|{title}|{now.date()}".encode()).hexdigest()[:12]
    return {"id": eid, "watch": watch["id"], "watchName": watch["name"], "ts": iso(now), "level": level, "kind": kind,
            "title": title, "detail": detail, "cves": list(cves)[:25], "links": [l for l in links if l.get("u")][:6]}


def run(now: datetime) -> dict:
    wl = read_json(W / "watchlist.json", {}) or {}
    state = read_json(W / "state.json", {}) or {}
    idx = read_json(CVES / "index.json", {}) or {}
    F = idx.get("fields") or []
    rows = [dict(zip(F, x)) for x in idx.get("items") or []]
    epss = (read_json(CVES / "epss.json", {}) or {}).get("scores") or {}
    advs = Repo(DATA_DIR / "advisories").recent(now, 45)
    events: list[dict] = []
    new_state: dict[str, dict] = {}

    for w in wl.get("watches") or []:
        prev = state.get(w["id"]) or {}
        baseline = not prev
        min_cvss = float(w.get("minCvss") or 0)
        focus = set(w.get("cves") or [])
        mine = [r for r in rows if matches_cve(w, r)]
        ids = {r["cve"] for r in mine} | focus
        prev_ids = set(prev.get("ids") or [])
        # ---- detailed signals for focus CVEs, KEV/ITW ones and anything at or above minCvss
        detailed = {r["cve"] for r in mine if (r.get("cvss") or 0) >= min_cvss or r.get("kev") or r.get("itw")} | focus
        sig_prev = prev.get("signals") or {}
        sig = {}
        for cid in sorted(detailed):
            s = cve_signals(cid, epss)
            if s:
                sig[cid] = s
        # ---- advisories
        adv_hits = {f"{a['src']}|{a['id']}": a for a in advs if matches_adv(w, a, ids)}
        adv_prev = prev.get("advisories") or {}
        ws = {"ids": sorted(ids), "signals": {c: {k: v for k, v in s.items() if k not in ("vendor", "product", "title")}
                                                for c, s in sig.items()},
              "advisories": {k: (a.get("updated") or a.get("released") or "")[:19] for k, a in adv_hits.items()},
              "updatedAt": iso(now)}
        new_state[w["id"]] = ws
        if baseline:
            events.append(ev(w, "info", "baseline", f"Watch started: {w['name']}",
                             f"Now watching {len(ids):,} CVEs ({len(sig):,} in detail) and {len(adv_hits):,} recent advisories. "
                             "Changes from the next update onward will be alerted.", now))
            continue
        cvelink = lambda c: {"t": c, "u": f"{SITE}validate.html?cve={c}"}  # noqa: E731
        # new CVEs: one summary event
        recent = (now - timedelta(days=30)).strftime("%Y-%m-%d")
        pub = {r["cve"]: (r.get("published") or "")[:10] for r in mine}
        new = sorted(c for c in ids - prev_ids if pub.get(c, "") >= recent)     # newly published, not just newly cached
        if new:
            hi = sorted((c for c in new if c in sig and (sig[c]["cvss"] or 0) >= min_cvss),
                        key=lambda c: -(sig[c]["cvss"] or 0))
            lvl = "high" if any(sig.get(c, {}).get("kev") or sig.get(c, {}).get("itw") for c in new) else "medium"
            events.append(ev(w, lvl, "new_cves", f"{len(new)} new CVE{'s' if len(new) != 1 else ''} for {w['name']}",
                             f"{len(hi)} rated CVSS {min_cvss:g}+." + (" Highest: " + ", ".join(f"{c} ({sig[c]['cvss']})" for c in hi[:5]) + "." if hi else ""),
                             now, new[:25], [cvelink(c) for c in (hi or new)[:4]]))
        # escalations on detailed CVEs
        for cid, s in sig.items():
            p = sig_prev.get(cid)
            if p is None:
                continue
            name = f"{cid} ({s.get('vendor') or ''} {s.get('product') or ''})".replace("  ", " ").replace("( ", "(").replace(" )", ")")
            if s["kev"] and not p.get("kev"):
                events.append(ev(w, "critical", "kev_added", f"{name} added to CISA KEV",
                                 "CISA lists this CVE as known exploited. Federal agencies have a remediation deadline; treat as emergency.",
                                 now, [cid], [cvelink(cid), {"t": "CISA KEV", "u": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}]))
            new_src = sorted(set(s["srcs"]) - set(p.get("srcs") or []) - ({"CISA KEV"} if s["kev"] and not p.get("kev") else set()))
            if new_src:
                events.append(ev(w, "critical", "exploitation", f"New exploitation evidence for {name}",
                                 "Reported by: " + ", ".join(new_src) + ". Exploitation reports are not proof that a specific system was compromised.",
                                 now, [cid], [cvelink(cid)]))
            if s["poc"] and not p.get("poc"):
                events.append(ev(w, "high", "poc_first", f"First public PoC / exploit reference for {name}",
                                 f"{s['poc']} public exploit or proof-of-concept reference(s) now listed. PoC repositories are unvetted.",
                                 now, [cid], [cvelink(cid)]))
            if s.get("pct") is not None and s["pct"] >= 0.9 and (p.get("pct") or 0) < 0.9:
                events.append(ev(w, "high", "epss_jump", f"EPSS for {name} rose into the top 10%",
                                 f"EPSS {s['epss']:.2%} (percentile {s['pct']:.0%}), previously {(p.get('epss') or 0):.2%}.",
                                 now, [cid], [cvelink(cid)]))
            if s["cvss"] is not None and p.get("cvss") is not None and s["cvss"] != p["cvss"]:
                events.append(ev(w, "medium", "cvss_changed", f"CVSS for {name} changed {p['cvss']} → {s['cvss']}",
                                 "The scoring source revised the severity.", now, [cid], [cvelink(cid)]))
        # advisories
        new_adv = [a for k, a in adv_hits.items() if k not in adv_prev]
        revised = [a for k, a in adv_hits.items() if k in adv_prev and (a.get("updated") or "")[:19] > adv_prev[k]]
        for a in sorted(new_adv, key=lambda a: a.get("released") or "")[-15:]:
            hits = sorted(set(a.get("cves") or []) & focus)
            events.append(ev(w, "high" if hits or a.get("expl") else "medium", "advisory_new",
                             f"New advisory: {a.get('title') or a['id']}",
                             f"{a.get('vendor') or a['src']} · {a['id']} · {len(a.get('cves') or [])} CVE(s)"
                             + (f" incl. watched {', '.join(hits)}" if hits else "") + (" · exploitation reported" if a.get("expl") else ""),
                             now, a.get("cves") or [], [{"t": a["id"], "u": a.get("url")}]))
        for a in sorted(revised, key=lambda a: a.get("updated") or "")[-10:]:
            events.append(ev(w, "medium", "advisory_revised", f"Advisory revised: {a.get('title') or a['id']}",
                             f"{a.get('vendor') or a['src']} · {a['id']} · updated {(a.get('updated') or '')[:10]}",
                             now, a.get("cves") or [], [{"t": a["id"], "u": a.get("url")}]))

    # ---- write
    old = read_json(W / "alerts.json", {}) or {}
    cutoff = iso(now - timedelta(days=KEEP_DAYS))
    seen = {e["id"] for e in events}
    hist = events + [e for e in old.get("events") or [] if e["ts"] >= cutoff and e["id"] not in seen]
    hist.sort(key=lambda e: (e["ts"], -LEVEL_RANK[e["level"]]), reverse=True)
    meta = {"schemaVersion": 1, "generatedAt": iso(now),
            "watches": [{"id": w["id"], "name": w["name"], "cves": len(new_state.get(w["id"], {}).get("ids", [])),
                         "advisories": len(new_state.get(w["id"], {}).get("advisories", {}))} for w in wl.get("watches") or []]}
    write_json(W / "alerts.json", {**meta, "events": hist[:2000]})
    write_json(W / "latest.json", {**meta, "count": len(events), "events": events})
    (W / "state.json").write_text(json.dumps(new_state, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    write_rss(hist[:60], now)
    return {"events": len(events), "levels": {l: sum(1 for e in events if e["level"] == l) for l in LEVEL_RANK}}


def write_rss(events: list[dict], now: datetime) -> None:
    items = []
    for e in events:
        link = next((l["u"] for l in e.get("links") or [] if l.get("u")), SITE + "alerts.html")
        items.append(f"<item><title>{escape('[' + e['level'].upper() + '] ' + e['watchName'] + ': ' + e['title'])}</title>"
                     f"<link>{escape(link)}</link><guid isPermaLink=\"false\">aegis-watch-{e['id']}</guid>"
                     f"<pubDate>{datetime.fromisoformat(e['ts'].replace('Z', '+00:00')).strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate>"
                     f"<description>{escape(e['detail'])}</description></item>")
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel><title>AEGIS ThreatWatch — Watchlist alerts</title>'
           f"<link>{SITE}alerts.html</link><description>Changes for watched vendors, products and CVEs.</description>"
           f"<lastBuildDate>{now.strftime('%a, %d %b %Y %H:%M:%S +0000')}</lastBuildDate>" + "".join(items) + "</channel></rss>\n")
    (W / "alerts.xml").write_text(xml, encoding="utf-8")


if __name__ == "__main__":
    out = run(datetime.now(timezone.utc))
    print(f"Watch alerts: {out['events']} events {out['levels']}")
