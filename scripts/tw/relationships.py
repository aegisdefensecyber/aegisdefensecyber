"""Threat Map data from MITRE ATT&CK (replaces the former demonstration dataset).

Graph: ATT&CK group --attributed--> ATT&CK campaign --exploits--> CVE (named in the campaign's ATT&CK record)
                                    ATT&CK campaign --uses-->     exploitation technique (T1190, T1203, ...)
Every edge carries evidence: the ATT&CK record URL, the first cited report where ATT&CK provides one, the
record's modification date as reportDate, and the campaign's first/last-seen dates.

Industry / category: taken from the wording of the campaign's ATT&CK description ("targeted energy
and telecommunications organizations"); when the campaign text names none, the attributed group's
description is used and the link is drawn from the actor at low confidence.
IOCs: added by add_iocs() from CISA advisories that ATT&CK cites and from abuse.ch ThreatFox.
"""
from __future__ import annotations

import hashlib

import re
from typing import Any

from .common import safe_url
from .iocs import advisory_codes

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
EXPLOIT_TECHNIQUES = {"T1190", "T1203", "T1210", "T1211", "T1212", "T1068", "T1133", "T1189", "T1195"}


def _ext(obj: dict, source: str = "mitre-attack") -> dict:
    for r in obj.get("external_references") or []:
        if r.get("source_name") == source:
            return r
    return {}


def _first_citation(obj: dict) -> str | None:
    for r in obj.get("external_references") or []:
        if r.get("source_name") != "mitre-attack" and safe_url(r.get("url")):
            return r["url"]
    return None


SECTORS = [  # (label, regex on description text)
    ("Government", r"\bgovernment|ministr(?:y|ies)|diplomat|embass|public sector|municipal"),
    ("Defense & military", r"\bdefen[cs]e\b|military|armed forces"),
    ("Energy & utilities", r"\benergy\b|electric|utilit(?:y|ies)|oil and gas|nuclear|power grid"),
    ("Telecommunications", r"telecom"),
    ("Financial services", r"\bfinancial|\bbank|fintech|insurance"),
    ("Cryptocurrency", r"crypto(?:currency)?|blockchain|\bdefi\b"),
    ("Healthcare", r"health ?care|hospital|medical|pharma"),
    ("Technology & IT", r"\btechnology\b|software|managed service|cloud provider|semiconductor|(?-i:\bIT\b)"),
    ("Manufacturing", r"manufactur|industrial"),
    ("Aerospace", r"aerospace|aviation"),
    ("Transportation & logistics", r"transport|logistic|shipping|maritime|airline"),
    ("Education & research", r"universit|academ|education|research institut|think tank"),
    ("Media", r"\bmedia\b|journalis|news organi"),
    ("NGOs & civil society", r"\bNGO|non-governmental|nonprofit|non-profit|civil society|human rights|dissident"),
    ("Critical infrastructure", r"critical infrastructure"),
    ("Retail & hospitality", r"retail|hospitality|hotel|casino|gaming"),
    ("Legal", r"\blaw firm|\blegal\b"),
]
SECTOR_RX = [(lab, re.compile(rx, re.I)) for lab, rx in SECTORS]


def sectors(text: str) -> list[str]:
    clean = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    return [lab for lab, rx in SECTOR_RX if rx.search(clean)]


def defang(kind: str, v: str) -> str:
    if kind in ("sha256", "md5"):
        return v
    return v.replace("http", "hxxp").replace(".", "[.]")


def _day(ts: Any) -> str | None:
    return str(ts)[:10] if ts else None


def build_graph(bundle: dict, cve_info: dict[str, dict], version: str | None, now_iso: str) -> dict:
    objs = {o["id"]: o for o in bundle.get("objects", []) if not o.get("revoked") and not o.get("x_mitre_deprecated")}
    rels = [o for o in objs.values() if o.get("type") == "relationship"]
    campaigns = {i: o for i, o in objs.items() if o.get("type") == "campaign"}

    camp_cves: dict[str, set[str]] = {}
    for cid, c in campaigns.items():
        found = set(CVE_RE.findall(c.get("description") or ""))
        for r in rels:
            if r.get("source_ref") == cid:
                found |= set(CVE_RE.findall(r.get("description") or ""))
        if found:
            camp_cves[cid] = found

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_edge(src, dst, relation, why, url, report, first=None, last=None, conf="moderate", etype="MITRE ATT&CK"):
        u = safe_url(url)
        if not u or not report:
            return
        edges.append({"id": f"e{len(edges) + 1}", "source": src, "target": dst, "relation": relation, "confidence": conf,
                      "why": why, "evidence": {"type": etype, "url": u, "reportDate": report, "firstObserved": first,
                                               "lastObserved": last,
                                               "provenance": f"MITRE ATT&CK Enterprise {version or ''}".strip()}})

    for cid, cves in sorted(camp_cves.items(), key=lambda kv: _ext(campaigns[kv[0]]).get("external_id", "")):
        c = campaigns[cid]
        ref = _ext(c)
        cnode = f"k-{ref.get('external_id', cid)}"
        first, last = _day(c.get("first_seen")), _day(c.get("last_seen"))
        nodes[cnode] = {"id": cnode, "type": "campaign", "label": c.get("name", ref.get("external_id")),
                        "attackId": ref.get("external_id"), "url": safe_url(ref.get("url")),
                        "timeframe": f"{first or '?'} to {last or '?'}"}
        camp_url = ref.get("url")
        for cve in sorted(cves):
            info = cve_info.get(cve) or {}
            vnode = f"c-{cve}"
            nodes.setdefault(vnode, {"id": vnode, "type": "cve", "label": cve, "product": info.get("product"),
                                     "exploitation": "confirmed" if info.get("kev") else "reported",
                                     "kev": bool(info.get("kev")), "epss": info.get("epss"), "cvss": info.get("cvss")})
            add_edge(cnode, vnode, "exploits", f"The ATT&CK record for {nodes[cnode]['label']} names {cve} as exploited in the campaign.",
                     camp_url, _day(c.get("modified")), first, last,
                     conf="high" if info.get("kev") else "moderate")
        for r in rels:
            if r.get("source_ref") != cid:
                continue
            tgt = objs.get(r.get("target_ref")) or {}
            if r.get("relationship_type") == "attributed-to" and tgt.get("type") == "intrusion-set":
                g = _ext(tgt)
                anode = f"a-{g.get('external_id', tgt['id'])}"
                nodes.setdefault(anode, {"id": anode, "type": "actor", "label": tgt.get("name"),
                                         "aliases": [a for a in tgt.get("aliases") or [] if a != tgt.get("name")][:6],
                                         "classification": None, "motivation": None, "origin": None,
                                         "profile": safe_url(g.get("url")), "attackId": g.get("external_id")})
                add_edge(anode, cnode, "attributed", f"MITRE ATT&CK attributes {nodes[cnode]['label']} to {tgt.get('name')}.",
                         _first_citation(r) or camp_url, _day(r.get("modified")), first, last)
            elif r.get("relationship_type") == "uses" and tgt.get("type") == "attack-pattern":
                t = _ext(tgt)
                tid = t.get("external_id", "")
                if tid.split(".")[0] not in EXPLOIT_TECHNIQUES:
                    continue
                tnode = f"t-{tid}"
                nodes.setdefault(tnode, {"id": tnode, "type": "technique", "label": f"{tid} {tgt.get('name')}",
                                         "url": safe_url(t.get("url"))})
                add_edge(cnode, tnode, "uses", f"ATT&CK records {nodes[cnode]['label']} using {tid}.",
                         _first_citation(r) or camp_url, _day(r.get("modified")), first, last)
    # ---- industry / category
    def ind_node(label):
        nid = "i-" + re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
        nodes.setdefault(nid, {"id": nid, "type": "industry", "label": label})
        return nid
    for cid in camp_cves:
        c = campaigns[cid]
        cnode = f"k-{_ext(c).get('external_id', cid)}"
        if cnode not in nodes:
            continue
        found = sectors(c.get("description") or "")
        first, last = _day(c.get("first_seen")), _day(c.get("last_seen"))
        for sec in found:
            add_edge(cnode, ind_node(sec), "observed_targeting",
                     f"MITRE ATT&CK's description of {nodes[cnode]['label']} names targets in: {sec}.",
                     _ext(c).get("url"), _day(c.get("modified")), first, last)
        if found:
            continue
        for r in rels:   # fall back to the attributed group's description (actor-level, low confidence)
            tgt = objs.get(r.get("target_ref")) or {}
            if r.get("source_ref") == cid and r.get("relationship_type") == "attributed-to" and tgt.get("type") == "intrusion-set":
                anode = f"a-{_ext(tgt).get('external_id', tgt['id'])}"
                for sec in sectors(tgt.get("description") or ""):
                    if not any(e["source"] == anode and e["target"] == ind_node(sec) for e in edges):
                        add_edge(anode, ind_node(sec), "observed_targeting",
                                 f"MITRE ATT&CK's profile of {tgt.get('name')} names {sec} among its targets.",
                                 _ext(tgt).get("url"), _day(tgt.get("modified")), conf="low")
    return {
        "schemaVersion": 1,
        "dataset": {"status": "verified",
                    "label": f"Relationships from MITRE ATT&CK Enterprise {version or ''}: groups, their campaigns, the CVEs "
                             "and exploitation techniques used, targeted industries, and indicators of compromise from CISA "
                             "advisories and abuse.ch ThreatFox. Every link cites its source.",
                    "updatedAt": now_iso, "source": "https://attack.mitre.org/campaigns/"},
        "nodes": list(nodes.values()),
        "edges": edges,
    }


# ATT&CK malware names that ThreatFox uses for an unrelated family (searching them would mislabel IOCs)
NAME_CLASH = {"MEDUSA"}   # UNC3886 rootkit vs ThreatFox "Medusa" botnet/ransomware


def ioc_queries(graph: dict, bundle: dict) -> tuple[dict[str, set[str]], dict[str, list[str]]]:
    """CISA advisory codes cited by ATT&CK for each mapped campaign/actor node, and ThreatFox search terms
    per actor: the actor's name, then the malware families ATT&CK says it uses."""
    by_ext, by_id = {}, {}
    for o in bundle.get("objects", []):
        by_id[o.get("id")] = o
        if o.get("type") in ("campaign", "intrusion-set") and not o.get("revoked"):
            by_ext[_ext(o).get("external_id")] = o
    uses: dict[str, list[str]] = {}
    for r in bundle.get("objects", []):
        if r.get("type") == "relationship" and r.get("relationship_type") == "uses" and not r.get("revoked"):
            m = by_id.get(r.get("target_ref")) or {}
            src = by_id.get(r.get("source_ref")) or {}
            if m.get("type") == "malware" and not m.get("revoked") and m.get("name") and src.get("type") == "intrusion-set":
                uses.setdefault(r.get("source_ref"), []).append(m["name"])
    users: dict[str, int] = {}
    for fams in uses.values():
        for f in set(fams):
            users[f] = users.get(f, 0) + 1
    codes: dict[str, set[str]] = {}
    names: dict[str, list[str]] = {}
    for n in graph["nodes"]:
        if n["type"] in ("campaign", "actor"):
            o = by_ext.get(n.get("attackId")) or {}
            c = advisory_codes(o)
            if c:
                codes[n["id"]] = c
            if n["type"] == "actor":
                # skip commodity malware shared by many groups (e.g. Cobalt Strike); most specific first
                fams = sorted({f for f in uses.get(o.get("id"), []) if users.get(f, 0) <= 3 and f.upper() not in NAME_CLASH},
                              key=lambda f: (users.get(f, 0), f))
                names[n["label"]] = [n["label"]] + fams
    return codes, names


def add_iocs(graph: dict, codes: dict[str, set[str]], cisa: dict[str, list[dict]], threatfox: dict[str, list[dict]],
             now_iso: str, max_iocs: int = 60) -> int:
    """Add IOC nodes and edges in place; returns how many IOC nodes were added."""
    nodes = {n["id"]: n for n in graph["nodes"]}
    edges = graph["edges"]
    added = 0

    def put(owner: str, i: dict, conf: str, why: str):
        nonlocal added
        url = safe_url(i.get("url"))
        if not url or owner not in nodes:
            return
        nid = "o-" + hashlib.sha1(i["value"].encode()).hexdigest()[:12]
        if nid not in nodes:
            if added >= max_iocs:
                return
            nodes[nid] = {"id": nid, "type": "ioc", "label": defang(i["type"], i["value"])[:80], "iocType": i["type"],
                          "source": i["source"], "ref": i.get("ref"), "firstSeen": i.get("seen") or None,
                          "malware": i.get("malware")}
            graph["nodes"].append(nodes[nid])
            added += 1
        if any(e["source"] == owner and e["target"] == nid for e in edges):
            return
        edges.append({"id": f"e{len(edges) + 1}", "source": owner, "target": nid, "relation": "indicator",
                      "confidence": conf, "why": why,
                      "evidence": {"type": i["source"], "url": url, "reportDate": i.get("seen") or now_iso[:10],
                                   "firstObserved": i.get("seen") or None, "lastObserved": i.get("seen") or None,
                                   "provenance": i.get("ref") or i["source"], "report": safe_url(i.get("report"))}})

    for owner, cs in sorted(codes.items()):
        for code in sorted(cs):
            for i in cisa.get(code, []):
                put(owner, i, "high", f"CISA advisory {code.upper()}, which MITRE ATT&CK cites for "
                                      f"{nodes[owner]['label']}, lists this indicator.")
    for n in list(graph["nodes"]):
        if n["type"] != "actor":
            continue
        for i in threatfox.get(n["label"], []):
            lvl = i.get("confidenceLevel") or 0
            put(n["id"], i, "low" if i.get("via") else "high" if lvl >= 75 else "moderate" if lvl >= 50 else "low",
                (f"abuse.ch ThreatFox lists this indicator for {i['via']}, malware MITRE ATT&CK attributes to {n['label']}"
                 if i.get("via") else f"abuse.ch ThreatFox tags this indicator {n['label']}"
                 + (f" ({i['malware']})" if i.get("malware") else ""))
                + f"; reporter confidence {lvl}%.")
    return added


def _sentence(text: str, cve: str, limit: int = 320) -> str:
    """The sentence of an ATT&CK description that mentions the CVE, citations stripped."""
    t = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    t = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", t)
    for s in re.split(r"(?<=[.!?])\s+", t):
        if cve in s:
            s = " ".join(s.split())
            return s if len(s) <= limit else s[: limit - 1] + "…"
    return ""


def build_cve_index(bundle: dict, now_iso: str) -> dict:
    """Every CVE that MITRE ATT&CK ties to a group, campaign or malware, with the technique and the sentence.

    Lets the Threat Map draw relationships for CVEs outside the default view when a researcher searches them.
    Malware mentions are attributed to the groups ATT&CK says use that malware (lower confidence).
    """
    objs = {o["id"]: o for o in bundle.get("objects", []) if not o.get("revoked") and not o.get("x_mitre_deprecated")}

    def ref(o):
        e = _ext(o)
        return e.get("external_id"), e.get("url")

    users: dict[str, list[str]] = {}          # malware/tool id -> group ids that use it
    for r in objs.values():
        if r.get("type") == "relationship" and r.get("relationship_type") == "uses":
            s, t = objs.get(r.get("source_ref")), objs.get(r.get("target_ref"))
            if s and t and s["type"] == "intrusion-set" and t["type"] in ("malware", "tool"):
                users.setdefault(t["id"], []).append(s["id"])

    out: dict[str, list[dict]] = {}

    def add(cve, who, tech, why, conf, via=None):
        if who.get("type") not in ("intrusion-set", "campaign"):
            return
        wid, wurl = ref(who)
        if not wid:
            return
        tid, turl = ref(tech) if tech else (None, None)
        row = {"kind": "actor" if who["type"] == "intrusion-set" else "campaign", "attackId": wid, "name": who.get("name"),
               "url": wurl, "aliases": [a for a in (who.get("aliases") or []) if a != who.get("name")][:6],
               "technique": {"id": tid, "name": tech.get("name"), "url": turl} if tid else None,
               "why": why, "confidence": conf, "via": via}
        rows = out.setdefault(cve, [])
        key = (row["attackId"], tid, via)
        if not any((x["attackId"], (x["technique"] or {}).get("id"), x["via"]) == key for x in rows):
            rows.append(row)

    for r in objs.values():
        if r.get("type") != "relationship" or r.get("relationship_type") != "uses":
            continue
        desc = r.get("description") or ""
        cves = set(CVE_RE.findall(desc))
        if not cves:
            continue
        s, t = objs.get(r.get("source_ref")), objs.get(r.get("target_ref"))
        if not s or not t:
            continue
        tech = t if t.get("type") == "attack-pattern" else None
        for c in cves:
            why = _sentence(desc, c)
            if s["type"] in ("intrusion-set", "campaign"):
                add(c, s, tech, why, "high")
            elif s["type"] in ("malware", "tool"):
                for g in users.get(s["id"], []):
                    add(c, objs[g], tech, why, "moderate", via=s.get("name"))
    for o in objs.values():                    # CVEs named in group/campaign/malware descriptions
        if o.get("type") not in ("intrusion-set", "campaign", "malware", "tool"):
            continue
        for c in set(CVE_RE.findall(o.get("description") or "")):
            why = _sentence(o.get("description") or "", c)
            if o["type"] in ("intrusion-set", "campaign"):
                add(c, o, None, why, "high")
            else:
                for g in users.get(o["id"], []):
                    add(c, objs[g], None, why, "moderate", via=o.get("name"))
    return {"schemaVersion": 1, "generatedAt": now_iso, "source": "MITRE ATT&CK Enterprise",
            "attackVersion": bundle.get("version") if isinstance(bundle, dict) else None,
            "count": len(out), "cves": {k: out[k] for k in sorted(out)}}
