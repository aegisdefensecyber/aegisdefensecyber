"""Indicators of compromise (IOCs) for the Threat Map.

Two sources, both cited on every IOC:

  CISA   Joint cybersecurity advisories (AAyy-nnnX) publish a STIX JSON file of IOCs.
         We only use advisories that MITRE ATT&CK itself cites for a mapped campaign or
         actor, so each IOC is tied to that campaign/actor by ATT&CK's own reference.
  abuse.ch ThreatFox
         Community IOC feed. Queried by the actor's name as a tag; needs a free
         Auth-Key (env THREATFOX_AUTH_KEY). Skipped without a key. ThreatFox only
         returns IOCs seen in the last six months.

Network problems never raise: a source that fails returns nothing and the caller keeps
the previous IOCs from that source. Values are stored as plain text and shown defanged.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from .common import USER_AGENT, fetch_json, fetch_text, safe_url

ADVISORY_RE = re.compile(r"\b(aa\d{2}-\d{3}[a-z])\b", re.I)
STIX_LINK_RE = re.compile(r'href=["\'](?:https?://(?:www\.)?cisa\.gov)?(/sites/default/files/[^"\'?#]+?\.json)(?:[?#][^"\']*)?["\']', re.I)
FILE_LINK_RE = re.compile(r'href=["\'](?:https?://(?:www\.)?cisa\.gov)?(/sites/default/files/[^"\'?#]+)', re.I)
DIAG: list[str] = []   # per-source notes printed by the catalog build
PATTERNS = [  # (STIX pattern regex, our ioc type)
    (re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'"), "ipv4"),
    (re.compile(r"ipv6-addr:value\s*=\s*'([^']+)'"), "ipv6"),
    (re.compile(r"domain-name:value\s*=\s*'([^']+)'"), "domain"),
    (re.compile(r"url:value\s*=\s*'([^']+)'"), "url"),
    (re.compile(r"file:hashes\.'?SHA-256'?\s*=\s*'([0-9a-fA-F]{64})'"), "sha256"),
    (re.compile(r"file:hashes\.'?MD5'?\s*=\s*'([0-9a-fA-F]{32})'"), "md5"),
]
PREFER = {"domain": 0, "ipv4": 1, "sha256": 2, "url": 3, "ipv6": 4, "md5": 5}
VALUE_OK = re.compile(r"^[\w.:/\-?=&%@\[\]~+]{3,300}$")
CISA_BASE = "https://www.cisa.gov/news-events/cybersecurity-advisories/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


def advisory_codes(obj: dict) -> set[str]:
    out = set()
    for r in obj.get("external_references") or []:
        u = str(r.get("url") or "")
        if "cisa.gov" in u:
            out |= {m.lower() for m in ADVISORY_RE.findall(u)}
    return out


def stix_iocs(doc: Any, limit: int) -> list[dict]:
    found: list[dict] = []
    for o in (doc or {}).get("objects") or []:
        if o.get("type") != "indicator":
            continue
        pat = str(o.get("pattern") or "")
        for rx, kind in PATTERNS:
            for v in rx.findall(pat):
                if VALUE_OK.match(v):
                    found.append({"type": kind, "value": v, "seen": str(o.get("valid_from") or o.get("created") or "")[:10]})
    found.sort(key=lambda i: (PREFER.get(i["type"], 9), i["value"]))
    seen, out = set(), []
    for i in found:
        if i["value"] not in seen:
            seen.add(i["value"])
            out.append(i)
    return out[:limit]


def cisa_iocs(codes: set[str], per_advisory: int = 4, max_advisories: int = 15) -> tuple[dict[str, list[dict]], bool]:
    """{advisory code: [ioc...]} and whether every fetch worked."""
    out: dict[str, list[dict]] = {}
    ok = True
    for code in sorted(codes, reverse=True)[:max_advisories]:   # newest advisories first
        page_url = CISA_BASE + code
        try:
            html = fetch_text(page_url, timeout=40, retries=2, limit_mb=8)
            found = STIX_LINK_RE.findall(html)
            links = sorted(found, key=lambda l: (0 if "stix" in l.lower() else 1 if code in l.lower() else 2))
            if not links:
                files = sorted(set(FILE_LINK_RE.findall(html)))[:6]
                DIAG.append(f"CISA {code}: no STIX JSON link; file links on page: {files or 'none'}")
                continue
            doc = fetch_json("https://www.cisa.gov" + links[0], timeout=40, retries=2)
            iocs = stix_iocs(doc, per_advisory)
            for i in iocs:
                i.update({"source": "CISA advisory", "url": page_url, "ref": code.upper()})
            DIAG.append(f"CISA {code}: {len(iocs)} IOCs from {links[0]}")
            if iocs:
                out[code] = iocs
        except Exception as exc:   # noqa: BLE001 — one bad advisory must not stop the rest
            DIAG.append(f"CISA {code}: failed ({str(exc)[:160]})")
            ok = False
    return out, ok


def _threatfox(body: dict, key: str) -> Any:
    req = urllib.request.Request(THREATFOX_API, data=json.dumps(body).encode(), method="POST",
                                 headers={"User-Agent": USER_AGENT, "Auth-Key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.loads(r.read(20 * 1024 * 1024))


def threatfox_iocs(queries, per_name: int = 4) -> tuple[dict[str, list[dict]], bool]:
    """{actor name: [ioc...]} from ThreatFox. queries maps an actor name to search terms: its own name,
    then the malware families MITRE ATT&CK says it uses (ThreatFox labels indicators by malware family).
    ({}, True) when no key is configured."""
    if isinstance(queries, list):
        queries = {q: [q] for q in queries}
    key = (os.environ.get("THREATFOX_AUTH_KEY") or "").strip()
    if not key or os.environ.get("TW_FIXTURES"):
        if not key:
            DIAG.append("ThreatFox: THREATFOX_AUTH_KEY not set, skipped")
        return {}, True
    out: dict[str, list[dict]] = {}
    ok = True
    kind = {"ip:port": "ipv4", "domain": "domain", "url": "url", "sha256_hash": "sha256", "md5_hash": "md5"}
    cache: dict[str, list] = {}

    def search(term: str, first: bool) -> list:
        nonlocal ok
        if term in cache:
            return cache[term]
        data: list = []
        bodies = [{"query": "taginfo", "tag": term, "limit": 20}]
        if not first:
            bodies.append({"query": "malwareinfo", "malware": term, "limit": 20})
        for body in bodies:
            try:
                doc = _threatfox(body, key)
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                DIAG.append(f"ThreatFox {term}: failed ({str(exc)[:120]})")
                ok = False
                break
            if doc.get("query_status") == "ok" and isinstance(doc.get("data"), list) and doc["data"]:
                data = doc["data"]
                DIAG.append(f"ThreatFox {term} ({body['query']}): {len(data)} rows")
                break
        cache[term] = data
        return data

    for name, terms in queries.items():
        rows = []
        for ti, term in enumerate(terms[:9]):
            for d in search(term, ti == 0):
                v = str(d.get("ioc") or "")
                t = kind.get(d.get("ioc_type"))
                if not t or not VALUE_OK.match(v):
                    continue
                conf = int(d.get("confidence_level") or 0)
                rows.append({"type": t, "value": v, "seen": str(d.get("first_seen") or "")[:10],
                             "malware": d.get("malware_printable"), "confidenceLevel": conf, "via": term if ti else None,
                             "source": "abuse.ch ThreatFox", "ref": f"ThreatFox #{d.get('id')}",
                             "url": safe_url(f"https://threatfox.abuse.ch/ioc/{d.get('id')}/"),
                             "report": safe_url(d.get("reference"))})
            if len(rows) >= per_name:
                break
        if not rows:
            DIAG.append(f"ThreatFox {name}: nothing for {', '.join(terms[:9])}")
        rows.sort(key=lambda r: (-r["confidenceLevel"], r["seen"]), reverse=False)
        if rows:
            out[name] = rows[:per_name]
    return out, ok
