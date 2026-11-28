#!/usr/bin/env python3
"""Record a human review of AI-drafted threat intelligence briefings.

    python scripts/approve_briefing.py --editor "Marcel Dera" 2026-11-28-linux.json [more files]
    python scripts/approve_briefing.py --list            # briefings whose review is pending

Run this on the briefing's pull-request branch after reading the draft against its sources, then
merge the pull request. scripts/validate_data.py blocks unreviewed briefings from reaching main.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tw.common import DATA_DIR, read_json, write_json  # noqa: E402

OUT = DATA_DIR / "briefings"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--editor", help="name recorded as the reviewing editor")
    ap.add_argument("--note", help="optional review note shown with the briefing")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("files", nargs="*")
    a = ap.parse_args()
    if a.list:
        for p in sorted(OUT.glob("20*.json")):
            if (read_json(p, {}) or {}).get("review", {}).get("status") == "pending":
                print(p.name)
        return 0
    if not a.editor or not a.editor.strip() or not a.files:
        print("usage: approve_briefing.py --editor NAME FILE [FILE...]", file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    idx = read_json(OUT / "index.json", {}) or {}
    for f in a.files:
        p = OUT / Path(f).name
        b = read_json(p)
        if not b:
            print(f"not found: {p}", file=sys.stderr)
            return 1
        b["review"] = {"status": "reviewed", "by": a.editor.strip()[:80], "at": now}
        if a.note:
            b["review"]["note"] = a.note.strip()[:300]
        write_json(p, b)
        for item in idx.get("briefings") or []:
            if item.get("file") == p.name:
                item["review"] = "reviewed"
        print(f"Reviewed {p.name} by {a.editor.strip()} at {now}")
    write_json(OUT / "index.json", idx)
    return 0


if __name__ == "__main__":
    sys.exit(main())
