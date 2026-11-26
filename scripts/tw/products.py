"""Vendor / product suggestions for the Vulnerability Validation search box.

Built from the vendors and products that actually have CVEs in the catalog (NVD affected-product
CPE data, CISA KEV and vendor advisories), ranked by how many CVEs each has. Major vendors only:
a vendor needs MIN_CVES catalog CVEs or a CISA KEV entry. Written as small per-letter files
(threatwatch/data/cpe/<x>.json) that the page loads only while someone types.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from .common import write_json

MIN_CVES = 3
MAX_PRODUCTS = 60
KEYS = "abcdefghijklmnopqrstuvwxyz0123456789"


def norm(s: str | None) -> str:
    s = re.sub(r"[^a-z0-9.+\-]+", "_", str(s or "").strip().lower()).strip("_")
    return s[:80]


def build(records: dict, root: Path, now_iso: str) -> dict:
    vend: dict[str, set[str]] = defaultdict(set)              # vendor -> CVEs
    prod: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    kev_vendors: set[str] = set()
    for cid, r in records.items():
        pairs = {(a.get("vendor"), a.get("product")) for a in r.get("affected") or []}
        if r.get("kev"):
            v = norm(r.get("vendor"))
            if v:
                kev_vendors.add(v)
        if not pairs and r.get("vendor"):
            pairs = {(r.get("vendor"), re.sub(r"\s*\(\+\d+ other products?\)$", "", r.get("product") or ""))}
        for v, p in pairs:
            v, p = norm(v), norm(p)
            if not v or v in ("n_a", "na", "unknown"):
                continue
            vend[v].add(cid)
            if p and p not in ("n_a", "na", "unknown"):
                prod[v][p].add(cid)
    keep = {v for v, c in vend.items() if len(c) >= MIN_CVES or v in kev_vendors}
    buckets: dict[str, dict] = defaultdict(dict)
    for v in sorted(keep):
        top = sorted(prod[v].items(), key=lambda kv: (-len(kv[1]), kv[0]))[:MAX_PRODUCTS]
        b = v[0] if v[0] in KEYS else "_"
        buckets[b][v] = {"n": len(vend[v]), "products": [[p, len(c)] for p, c in top]}
    root.mkdir(parents=True, exist_ok=True)
    for old in root.glob("*.json"):
        old.unlink()
    for b, vendors in buckets.items():
        write_json(root / f"{b}.json", {"schemaVersion": 2, "vendors": vendors})
    meta = {"schemaVersion": 2, "generatedAt": now_iso, "vendors": len(keep),
            "products": sum(len(x["products"]) for vs in buckets.values() for x in vs.values()),
            "rule": f"vendors with at least {MIN_CVES} catalog CVEs or a CISA KEV entry; top {MAX_PRODUCTS} products each"}
    write_json(root / "state.json", meta)
    return meta
