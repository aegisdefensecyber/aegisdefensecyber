"""Advisory repository on disk: one small JSON file per release day (threatwatch/data/advisories/days/).

* Every advisory is kept whole (one entry, all its CVEs) — including advisories with no CVE ID.
* Re-collected advisories replace their earlier copy in place (same source + id); `seen` keeps the
  date AEGIS first collected it, `updated` the source's own modified date, so new vs updated is clear.
* Files are never pruned: history beyond 90 days is retained. Only days whose content changed are
  rewritten, which keeps repository growth to real changes.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

from .common import write_json

KEEP = ("id", "src", "vendor", "title", "url", "released", "updated", "seen", "cves", "sev", "cvss",
        "products", "fix", "expl", "lang", "reviewed")


def _day(r: dict) -> str:
    return (r.get("released") or r.get("updated") or r.get("seen") or "0000-00-00")[:10]


def worth_keeping(r: dict) -> bool:
    """GitHub's unreviewed advisories mirror every CVE with no package data: those duplicate the CVE List."""
    if r.get("src") == "github" and r.get("reviewed") is False and not r.get("products"):
        return False
    return True


class Repo:
    def __init__(self, root: Path):
        self.root = root / "days"
        self.root.mkdir(parents=True, exist_ok=True)
        self.cache: dict[str, dict[tuple, dict]] = {}
        self.dirty: set[str] = set()
        self.added = self.changed = 0

    def _load(self, day: str) -> dict[tuple, dict]:
        if day not in self.cache:
            p = self.root / f"{day}.json"
            items = json.loads(p.read_text(encoding="utf-8")).get("items", []) if p.exists() else []
            self.cache[day] = {(i["src"], i["id"]): i for i in items}
        return self.cache[day]

    def upsert(self, recs: Iterable[dict], now_iso: str) -> None:
        for r in recs:
            if not worth_keeping(r):
                continue
            r = {k: r.get(k) for k in KEEP if r.get(k) not in (None, "", [])}
            day = _day(r)
            if day.startswith("0000"):
                continue
            items = self._load(day)
            key = (r["src"], r["id"])
            old = items.get(key)
            r["seen"] = (old or {}).get("seen") or now_iso[:10]
            if old != r:
                items[key] = r
                self.dirty.add(day)
                if old:
                    self.changed += 1
                else:
                    self.added += 1

    def flush(self, now_iso: str) -> int:
        for day in sorted(self.dirty):
            items = sorted(self.cache[day].values(), key=lambda i: (i.get("released") or "", i["src"], i["id"]))
            write_json(self.root / f"{day}.json", {"schemaVersion": 1, "date": day, "count": len(items), "items": items})
        self._index(now_iso)
        n = len(self.dirty)
        self.dirty.clear()
        return n

    def _index(self, now_iso: str) -> None:
        idx_path = self.root / "index.json"
        idx = json.loads(idx_path.read_text(encoding="utf-8")) if idx_path.exists() else {"days": {}}
        for day in self.dirty:
            items = self.cache[day].values()
            by_src: dict[str, int] = {}
            for i in items:
                by_src[i["src"]] = by_src.get(i["src"], 0) + 1
            idx["days"][day] = {"count": len(self.cache[day]), "noCve": sum(1 for i in items if not i.get("cves")),
                                "sources": by_src}
        idx.update({"schemaVersion": 1, "generatedAt": now_iso,
                    "total": sum(d["count"] for d in idx["days"].values()), "days": dict(sorted(idx["days"].items()))})
        write_json(idx_path, idx)

    def recent(self, now: datetime, days: int = 90) -> list[dict]:
        out = []
        for i in range(days + 1):
            d = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            if (self.root / f"{d}.json").exists() or d in self.cache:
                out.extend(self._load(d).values())
        return out
