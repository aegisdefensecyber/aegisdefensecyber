#!/usr/bin/env python3
"""Validate a threat intelligence briefing (Layer 2) and add it to threatwatch/data/briefings/.

Usage:
    python scripts/publish_briefing.py --draft path/to/briefing.json   # AI draft, review pending
    python scripts/publish_briefing.py path/to/briefing.json           # needs review.status "reviewed"

The briefing task writes the JSON; this script enforces the schema, safe links and sizes,
writes data/briefings/<date>-<watch>.json and updates data/briefings/index.json.

Human review gate: every briefing names who drafted it (`draftedBy`) and carries a `review`
object. Drafts are written with review.status "pending" on a pull-request branch; a person
approves them with scripts/approve_briefing.py, and scripts/validate_data.py rejects any
briefing dated on or after REVIEW_GATE_FROM that reaches main without a completed review.
Corrections are appended to `corrections` and stay visible; they are never silently overwritten.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tw.common import DATA_DIR, read_json, safe_url, write_json  # noqa: E402

OUT = DATA_DIR / "briefings"
PRIORITIES = ("EMERGENCY", "HIGH", "ELEVATED", "ROUTINE")
REVIEW_STATUSES = ("reviewed", "pending", "not-reviewed")
REVIEW_GATE_FROM = "2026-11-28"   # briefings dated on/after this must be human-reviewed before they reach main


def fail(msg: str) -> None:
    print(f"BRIEFING REJECTED: {msg}", file=sys.stderr)
    sys.exit(1)


def text(v, n, name) -> str:
    if not isinstance(v, str) or not v.strip():
        fail(f"{name} must be non-empty text")
    v = " ".join(v.split())
    if len(v) > n:
        fail(f"{name} longer than {n} characters")
    if re.search(r"<\s*/?\s*(script|iframe|img|a)\b", v, re.I):
        fail(f"{name} contains markup")
    return v


def rows(v, width, name, n=40) -> list[list[str]]:
    if v is None:
        return []
    if not isinstance(v, list) or len(v) > n:
        fail(f"{name} must be a list of at most {n} rows")
    out = []
    for r in v:
        if not isinstance(r, list) or len(r) != width:
            fail(f"each {name} row must have {width} cells")
        out.append([text(c, 400, name) for c in r])
    return out


def review_block(v, draft: bool) -> dict:
    if draft:
        return {"status": "pending"}
    if not isinstance(v, dict) or v.get("status") != "reviewed":
        fail('review.status must be "reviewed" (use --draft for an unreviewed AI draft, then approve_briefing.py)')
    at = v.get("at") or ""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?Z", at):
        fail("review.at must be a UTC timestamp like 2026-11-28T14:05:00Z")
    out = {"status": "reviewed", "by": text(v.get("by"), 80, "review.by"), "at": at}
    if v.get("note"):
        out["note"] = text(v["note"], 300, "review.note")
    return out


def corrections_list(v) -> list[dict]:
    out = []
    for c in v or []:
        if not isinstance(c, dict) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(c.get("date") or "")):
            fail("each correction needs a date (YYYY-MM-DD) and text")
        out.append({"date": c["date"], "text": text(c.get("text"), 900, "correction")})
    return out[:20]


def main(path: str, draft: bool = False) -> int:
    b = json.loads(Path(path).read_text(encoding="utf-8"))
    date = b.get("date") or ""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        fail("date must be YYYY-MM-DD")
    watch = b.get("watch") or ""
    if not re.fullmatch(r"[a-z0-9-]{2,40}", watch):
        fail("watch must be a watchlist id")
    if b.get("priority") not in PRIORITIES:
        fail(f"priority must be one of {PRIORITIES}")
    srcs = []
    for s in b.get("sources") or []:
        u = safe_url(s.get("url"))
        if not u:
            fail(f"unsafe or missing source url: {s.get('url')!r}")
        srcs.append({"title": text(s.get("title") or u, 200, "source title"), "url": u})
    if not srcs:
        fail("at least one source is required")
    clean = {
        "schemaVersion": 1, "date": date, "watch": watch, "watchName": text(b.get("watchName") or watch, 80, "watchName"),
        "priority": b["priority"], "title": text(b.get("title"), 160, "title"), "headline": text(b.get("headline"), 500, "headline"),
        "summary": text(b["summary"], 1500, "summary") if b.get("summary") else None,
        "changes": [text(c, 600, "changes") for c in (b.get("changes") or [])][:12],
        "assessment": rows(b.get("assessment"), 2, "assessment"), "affected": rows(b.get("affected"), 2, "affected"),
        "actions": rows(b.get("actions"), 3, "actions"), "monitoring": rows(b.get("monitoring"), 2, "monitoring"),
        "limitations": text(b["limitations"], 800, "limitations") if b.get("limitations") else None,
        "judgment": text(b.get("judgment"), 900, "judgment"), "sources": srcs[:20],
        "alertIds": [a for a in (b.get("alertIds") or []) if re.fullmatch(r"[0-9a-f]{12}", str(a))][:50],
        "draftedBy": text(b.get("draftedBy"), 120, "draftedBy"),
        "review": review_block(b.get("review"), draft),
        "corrections": corrections_list(b.get("corrections")),
    }
    if b.get("updatedAt"):
        clean["updatedAt"] = text(b["updatedAt"], 40, "updatedAt")
    OUT.mkdir(parents=True, exist_ok=True)
    name = f"{date}-{watch}.json"
    write_json(OUT / name, clean)
    idx = read_json(OUT / "index.json", {}) or {}
    items = [x for x in idx.get("briefings") or [] if x.get("file") != name]
    items.insert(0, {"file": name, "date": date, "watch": watch, "title": clean["title"], "priority": clean["priority"],
                     "headline": clean["headline"], "review": clean["review"]["status"],
                     "corrected": bool(clean["corrections"])})
    items.sort(key=lambda x: (x["date"], x["file"]), reverse=True)
    write_json(OUT / "index.json", {"schemaVersion": 1, "briefings": items[:400]})
    state = "DRAFT (review pending)" if draft else f"reviewed by {clean['review']['by']}"
    print(f"Wrote briefing {name} ({clean['priority']}, {state}): {clean['title']}")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    is_draft = "--draft" in args
    args = [a for a in args if a != "--draft"]
    if len(args) != 1:
        fail("usage: publish_briefing.py [--draft] briefing.json")
    sys.exit(main(args[0], is_draft))
