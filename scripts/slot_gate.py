#!/usr/bin/env python3
"""Cheap "is an update due?" check for the scheduled workflows.

GitHub's cron is best effort and on this repository it drops most fires, so the
workflows are woken every 15 minutes and this script decides, in a second or two
and without the full checkout, whether an update slot is due:

  threatwatch  due when the current ET slot (07:00/12:00/17:00/22:00, opening at
               :45 the hour before) has not been recorded in
               threatwatch/data/status.json → lastSlot.
  global       due when global-intelligence/data/last-updated.json → collected_at
               is older than the start of the current slot.

Writes due=true|false to $GITHUB_OUTPUT (when set) and prints the reason.
Standard library only.

Usage:  python3 scripts/slot_gate.py threatwatch|global [--now ISO8601]
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ET = ZoneInfo("America/New_York")
ROOT = Path(__file__).resolve().parent.parent
# Must match SLOTS_ET in scripts/build_brief.py
SLOTS = [((6, 45), "07:00"), ((11, 45), "12:00"), ((16, 45), "17:00"), ((21, 45), "22:00")]


def slot_at(now_et: datetime) -> tuple[str | None, datetime | None]:
    """(label, opening time) of the latest slot opened today, or (None, None) before the first."""
    label, start = None, None
    for (h, m), lab in SLOTS:
        opened = now_et.replace(hour=h, minute=m, second=0, microsecond=0)
        if now_et >= opened:
            label, start = lab, opened
    return label, start


def _read(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def threatwatch_due(now_et: datetime) -> tuple[bool, str]:
    label, _ = slot_at(now_et)
    if label is None:
        return False, f"{now_et:%H:%M} ET is before the first slot"
    key = f"{now_et:%Y-%m-%d} {label}"
    last = _read(ROOT / "threatwatch/data/status.json").get("lastSlot")
    if last == key:
        return False, f"slot {key} already ran"
    return True, f"slot {key} is due (last ran: {last or 'never'})"


def global_due(now_et: datetime) -> tuple[bool, str]:
    label, start = slot_at(now_et)
    if start is None:   # before 06:45: the previous evening's 22:00 slot is the current one
        y = now_et - timedelta(days=1)
        label, start = SLOTS[-1][1], y.replace(hour=SLOTS[-1][0][0], minute=SLOTS[-1][0][1],
                                                second=0, microsecond=0)
    collected = _parse(_read(ROOT / "global-intelligence/data/last-updated.json").get("collected_at"))
    if collected and collected >= start:
        return False, f"built {collected.astimezone(ET):%Y-%m-%d %H:%M} ET, after the {label} slot opened"
    return True, f"the {label} slot opened {start:%Y-%m-%d %H:%M} ET; last build " \
                 f"{collected.astimezone(ET):%Y-%m-%d %H:%M} ET" if collected else "no previous build"


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("threatwatch", "global"):
        print(__doc__, file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc)
    if "--now" in argv:
        now = _parse(argv[argv.index("--now") + 1]) or now
    now_et = now.astimezone(ET)
    due, why = (threatwatch_due if argv[0] == "threatwatch" else global_due)(now_et)
    print(f"{argv[0]}: {'DUE' if due else 'not due'} — {why}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"due={'true' if due else 'false'}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
