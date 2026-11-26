#!/usr/bin/env python3
"""Collect security advisories into the AEGIS advisory repository (runs twice a day).

Sources: CIRCL Vulnerability-Lookup (vendor & CERT CSAF, CERT-FR, JVN, NCSC-NL, CERT-Bund, CISA,
GitHub reviewed + unreviewed, OSV distro/package feeds, Debian, the CVE List…), plus direct CSAF
provider feeds, Fortinet PSIRT and Palo Alto Networks. Writes:
  threatwatch/data/advisories/days/YYYY-MM-DD.json   advisories by release day (history kept)
  threatwatch/data/advisories/days/index.json        per-day counts
  threatwatch/data/advisories/sources.json           source health (last success, lag, errors)
  threatwatch/data/advisories/state.json             collection cursors
The CVE catalog build (build_catalog.py) reads the day files to add vendor advisories and missing CVEs.
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tw.advrepo import Repo  # noqa: E402
from tw.common import DATA_DIR, read_json, write_json  # noqa: E402

ADV = DATA_DIR / "advisories"


def iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def direct_records(state: dict, deadline: float, health: dict) -> list[dict]:
    """Direct CSAF providers + Fortinet + Palo Alto, grouped back into whole advisories."""
    from tw import advisories as A
    rows, notes = [], []
    for name, fn in (("direct_csaf", lambda: A.collect_csaf(state, deadline, notes)[0]),
                     ("fortinet", lambda: A.parse_fortinet_rss(A._get(A.FORTINET_RSS, accept="application/rss+xml")[0].decode("utf-8", "replace"))),
                     ("paloalto", lambda: A.parse_panw(A._json(A.PANW_JSON)))):
        t0 = time.time()
        try:
            got = fn()
            rows += [dict(r, _src=name) for r in got]
            health[name] = {"ok": True, "records": len(got), "seconds": round(time.time() - t0)}
        except Exception as exc:  # noqa: BLE001
            health[name] = {"ok": False, "error": str(exc)[:200]}
    adv: dict[tuple, dict] = {}
    for r in rows:
        key = (r["_src"], r.get("id") or r.get("url") or r["cve"])
        a = adv.setdefault(key, {"id": str(key[1])[:120], "src": r["_src"], "vendor": r.get("vendor"), "title": r.get("title"),
                                 "url": r.get("url"), "released": r.get("released"), "updated": r.get("updated"),
                                 "cves": [], "sev": None, "cvss": None, "products": [], "fix": [], "expl": None})
        if r["cve"] not in a["cves"]:
            a["cves"].append(r["cve"])
        if r.get("cvss") is not None and (a["cvss"] is None or r["cvss"] > a["cvss"]):
            a["cvss"], a["sev"] = r["cvss"], r.get("severity")
        a["sev"] = a["sev"] or r.get("severity")
        for p in r.get("products") or []:
            if p not in a["products"] and len(a["products"]) < 6:
                a["products"].append(p)
        for f in r.get("fixes") or []:
            g = {"t": f.get("text"), "u": f.get("url")}
            if g not in a["fix"] and len(a["fix"]) < 3:
                a["fix"].append(g)
        if r.get("exploited"):
            a["expl"] = True
    return list(adv.values())


def main() -> int:
    now = datetime.now(timezone.utc)
    budget = float(os.environ.get("TW_ADV_BUDGET_S") or 1500)
    state = read_json(ADV / "state.json", {}) or {}
    prev_health = (read_json(ADV / "sources.json", {}) or {}).get("sources", {})
    repo = Repo(ADV)
    health: dict[str, dict] = {}

    from tw import circl
    ch = circl.collect(state, now, budget, on_records=lambda src, recs: repo.upsert(recs, iso(now)))
    health.update(ch)
    labels = {"direct_csaf": "Direct CSAF provider feeds", "fortinet": "Fortinet PSIRT", "paloalto": "Palo Alto Networks"}
    for k, v in _direct(state, {}, repo, now).items():
        health[k] = dict(v, label=labels[k], group="Vendor", complete=v.get("ok"))

    changed_days = repo.flush(iso(now))
    # older advisories updated in the last 14 days (their day file is outside a short date range)
    cutoff = (now - timedelta(days=14)).strftime("%Y-%m-%d")
    pool = {(i["src"], i["id"]): i for i in repo.recent(now, 120)}
    for items in repo.cache.values():
        pool.update(items)
    upd = [i for i in pool.values() if (i.get("updated") or "")[:10] >= cutoff and (i.get("released") or "")[:10] < (i.get("updated") or "")[:10]]
    upd.sort(key=lambda i: i.get("updated") or "", reverse=True)
    write_json(ADV / "updates.json", {"schemaVersion": 1, "generatedAt": iso(now), "sinceDay": cutoff, "count": len(upd), "items": upd[:5000]})
    idx = read_json(ADV / "days" / "index.json", {}) or {}
    stored: dict[str, int] = {}
    newest: dict[str, str] = {}
    for d, info in (idx.get("days") or {}).items():
        for s, n in (info.get("sources") or {}).items():
            stored[s] = stored.get(s, 0) + n
            newest[s] = max(newest.get(s, ""), d)
    out = {}
    for src, h in health.items():
        if src.startswith("_"):
            continue
        p = prev_health.get(src, {})
        ok = h.get("ok")
        last_ok = iso(now) if ok else p.get("lastSuccess")
        lag = None
        if newest.get(src):
            lag = round((now - datetime.strptime(newest[src], "%Y-%m-%d").replace(tzinfo=timezone.utc)).total_seconds() / 86400, 1)
        out[src] = {"label": h.get("label") or p.get("label") or src, "group": h.get("group") or p.get("group") or "Other",
                    "ok": ok, "lastAttempt": iso(now), "lastSuccess": last_ok, "recordsThisRun": h.get("records", 0),
                    "stored": stored.get(src, 0), "newestDay": newest.get(src), "daysSinceNewest": lag,
                    "backfillComplete": bool(h.get("complete")) or bool(p.get("backfillComplete")),
                    "note": h.get("note"), "error": h.get("error")}
    write_json(ADV / "sources.json", {"schemaVersion": 1, "generatedAt": iso(now), "circl": health.get("_circl"),
                                      "added": repo.added, "changed": repo.changed, "daysWritten": changed_days,
                                      "total": idx.get("total"), "sources": dict(sorted(out.items()))})
    write_json(ADV / "state.json", state)
    failing = [s for s, h in out.items() if h["ok"] is False]
    print(f"Advisories: +{repo.added} new, {repo.changed} updated, {changed_days} day files written, "
          f"{idx.get('total')} stored · CIRCL calls {(health.get('_circl') or {}).get('calls')}"
          + (f" · failing: {', '.join(failing)}" if failing else ""))
    return 0


def _direct(state: dict, health: dict, repo: Repo, now: datetime) -> dict:
    deadline = time.time() + float(os.environ.get("TW_ADV_DIRECT_S") or 300)
    recs = direct_records(state, deadline, health)
    repo.upsert(recs, iso(now))
    return health


if __name__ == "__main__":
    sys.exit(main())
