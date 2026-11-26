"""NVD CPE dictionary -> vendor/product name lists for the Vulnerability Validation search box.

The dictionary (~1.4M CPE names) is read through the NVD Products API in pages, a share per run, and
reduced to unique vendor -> products, saved as small per-letter files (threatwatch/data/cpe/<x>.json)
that the page loads only while someone types. After the first full pass only changes are fetched.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .common import fetch_json, read_json, write_json

API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
PAGE = 10000
PAGES_PER_RUN = int(os.environ.get("TW_CPE_PAGES") or 15)
KEYS = "abcdefghijklmnopqrstuvwxyz0123456789_"


def _bucket(vendor: str) -> str:
    c = (vendor[:1] or "_").lower()
    return c if c in KEYS[:-1] else "_"


def _split(name: str) -> tuple[str, str, str] | None:
    p = name.split(":")
    if len(p) < 6 or p[0] != "cpe" or p[2] not in ("a", "o", "h"):
        return None
    vendor, product = p[3].replace("\\", ""), p[4].replace("\\", "")
    if not vendor or vendor in ("*", "-") or not product or product in ("*", "-"):
        return None
    return p[2], vendor[:80], product[:100]


def reduce_page(items: list[dict]) -> dict[str, dict[str, set[str]]]:
    """{bucket: {vendor: {part:product}}} from one API page (deprecated names skipped)."""
    out: dict[str, dict[str, set[str]]] = {}
    for it in items:
        c = it.get("cpe") or {}
        if c.get("deprecated"):
            continue
        s = _split(str(c.get("cpeName") or ""))
        if s:
            part, v, p = s
            out.setdefault(_bucket(v), {}).setdefault(v, set()).add(f"{part}:{p}")
    return out


def _merge(root: Path, red: dict[str, dict[str, set[str]]]) -> None:
    for b, vendors in red.items():
        path = root / f"{b}.json"
        cur = read_json(path, {}) or {}
        data = cur.get("vendors") or {}
        for v, prods in vendors.items():
            data[v] = sorted(set(data.get(v, [])) | prods)
        write_json(path, {"schemaVersion": 1, "vendors": dict(sorted(data.items()))})


def refresh(root: Path, now: datetime, warnings: list[str]) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    st = read_json(root / "state.json", {}) or {}
    key = os.environ.get("NVD_API_KEY", "").strip()
    hdr = {"apiKey": key} if key else {}
    pause = 0.8 if key else 6.5
    pages = 0
    try:
        if not st.get("complete"):
            start = int(st.get("startIndex") or 0)
            while pages < PAGES_PER_RUN:
                d = fetch_json(f"{API}?resultsPerPage={PAGE}&startIndex={start}", headers=hdr, timeout=120, retries=2)
                items = d.get("products") or []
                _merge(root, reduce_page(items))
                total = int(d.get("totalResults") or 0)
                start += len(items)
                pages += 1
                st.update({"startIndex": start, "totalResults": total})
                if not items or start >= total:
                    st.update({"complete": True, "lastModified": now.strftime("%Y-%m-%dT%H:%M:%S.000Z")})
                    break
                time.sleep(pause)
        else:
            since = datetime.fromisoformat(st["lastModified"].replace("Z", "+00:00"))
            if now - since > timedelta(hours=20):
                since = max(since, now - timedelta(days=119))     # API window limit is 120 days
                start = 0
                fmt = "%Y-%m-%dT%H:%M:%S.000Z"
                while pages < PAGES_PER_RUN:
                    d = fetch_json(f"{API}?resultsPerPage={PAGE}&startIndex={start}&lastModStartDate={since.strftime(fmt)}"
                                   f"&lastModEndDate={now.strftime(fmt)}", headers=hdr, timeout=120, retries=2)
                    items = d.get("products") or []
                    _merge(root, reduce_page(items))
                    start += len(items)
                    pages += 1
                    if not items or start >= int(d.get("totalResults") or 0):
                        break
                    time.sleep(pause)
                st["lastModified"] = now.strftime(fmt)
    except Exception as exc:  # noqa: BLE001 — partial progress is kept; resumes next run
        warnings.append(f"CPE dictionary refresh paused ({exc})"[:300])
    st["updatedAt"] = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    st["vendors"] = sum(len((read_json(root / f"{b}.json", {}) or {}).get("vendors") or {}) for b in KEYS)
    write_json(root / "state.json", st)
    return st
