#!/usr/bin/env python3
"""Email copy of the morning ThreatWatch brief.

Renders the day's seven-section brief document as a self-contained, inline-styled
HTML email page at threatwatch/email/<edition>.html. The page is published with the
site, and the email service (Zoho Campaigns) fetches it by URL when the morning
campaign is created (see send_digest.py).

Only the morning edition gets an email page; the 12:00, 17:00 and 22:00 updates
refresh the website only. All feed text is HTML-escaped.

Usage:
  python scripts/build_digest.py              # (re)write the page for the latest edition
"""
from __future__ import annotations

import html
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tw.common import DATA_DIR, ET, read_json  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
EMAIL_DIR = DATA_DIR.parent / "email"   # threatwatch/email (follows TW_DATA_DIR in tests)
SITE_URL = "https://aegisdefensecyber.com"
KEEP = 14  # email pages kept online (two weeks)
UNSUBSCRIBE_TAG = "$[LI:UNSUBSCRIBE]$"   # Zoho Campaigns fills in each recipient's link

NAVY, BLUE, INK, MUTED, LINE = "#1d3a5f", "#1f4e79", "#1f2933", "#52606d", "#d9e2ec"
CONFIG = REPO_ROOT / "threatwatch" / "subscription-config.json"


def sender_identity() -> dict:
    """Legal sender name, postal address and privacy-notice URL for email footers (CAN-SPAM).

    Kept in threatwatch/subscription-config.json. send_digest.py and send_alerts.py refuse to send
    while postalAddress is empty, so no email ever goes out without a physical address.
    """
    cfg = read_json(CONFIG, {}) or {}
    return {"legalName": str(cfg.get("legalName") or "Aegis Cyber Solutions LLC").strip(),
            "postalAddress": str(cfg.get("postalAddress") or "").strip(),
            "privacyUrl": str(cfg.get("privacyUrl") or f"{SITE_URL}/privacy/").strip()}


def identity_footer_html(color: str) -> str:
    who = sender_identity()
    parts = [html.escape(who["legalName"])]
    if who["postalAddress"]:
        parts.append(html.escape(who["postalAddress"]))
    url = who["privacyUrl"] if who["privacyUrl"].startswith("https://") else f"{SITE_URL}/privacy/"
    return (" · ".join(parts) + f' · <a href="{html.escape(url, quote=True)}" style="color:{color}">Privacy notice</a>')
FONT = "Helvetica, Arial, sans-serif"


def _inline(text: str) -> str:
    """Escape, then turn **bold** into <strong>."""
    out = html.escape(text or "", quote=True)
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    # [label](https://…) → link (the URL was already HTML-escaped above, so no markup can be injected)
    return re.sub(r"\[([^\]]{1,120})\]\((https://[^\s)&;]+)\)",
                  lambda m: f'<a href="{m.group(2)}" style="color:{BLUE}">{m.group(1)}</a>', out)


def _block(b: dict) -> str:
    if b.get("type") == "p":
        return (f'<p style="margin:0 0 12px;font:15px/1.55 {FONT};color:{INK}">'
                f'{_inline(b.get("text", ""))}</p>')
    if b.get("type") == "table":
        head = "".join(f'<th align="left" style="background:{BLUE};color:#ffffff;font:bold 13px/1.4 {FONT};'
                       f'padding:8px 10px;border:1px solid {BLUE}">{_inline(c)}</th>'
                       for c in b.get("columns") or [])
        rows = ""
        for r in b.get("rows") or []:
            cells = "".join(f'<td valign="top" style="font:13px/1.45 {FONT};color:{INK};padding:7px 10px;'
                            f'border:1px solid {LINE}">{_inline(str(c))}</td>' for c in r)
            rows += f"<tr>{cells}</tr>"
        return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                f'style="border-collapse:collapse;margin:0 0 14px"><tr>{head}</tr>{rows}</table>')
    return ""


def render(brief: dict) -> tuple[str, str]:
    """Return (subject, html) for a brief."""
    rep = brief["report"]
    edition = brief["edition"]
    day = datetime.fromisoformat(edition).strftime("%B %-d, %Y")
    counts = (brief.get("executive") or {}).get("counts") or {}
    kev = counts.get("kevAdded") or 0
    subject = (f"AEGIS ThreatWatch — {day}: "
               + (f"{kev} new exploited vulnerabilit{'y' if kev == 1 else 'ies'}" if kev
                  else "daily zero-day brief"))
    web = f"{SITE_URL}/threatwatch/"
    sections = ""
    for s in rep.get("sections") or []:
        sections += (f'<h2 style="margin:26px 0 10px;font:bold 18px/1.3 {FONT};color:{NAVY};'
                     f'border-bottom:2px solid {BLUE};padding-bottom:6px">'
                     f'{int(s.get("num") or 0)}. {_inline(s.get("title", ""))}</h2>'
                     + "".join(_block(b) for b in s.get("blocks") or []))
    refs = "".join(f'<li style="margin:0 0 4px"><a href="{html.escape(r["url"], quote=True)}" '
                   f'style="color:{BLUE}">{_inline(r.get("label", ""))}</a></li>'
                   for r in (rep.get("references") or [])[:25] if str(r.get("url", "")).startswith("https://"))
    title = " ".join(rep.get("title") or ["THREAT INTELLIGENCE BRIEF"])
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex">
<title>{html.escape(subject)}</title></head>
<body style="margin:0;padding:0;background:#eef2f6">
<!-- tw-edition:{html.escape(edition)} -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef2f6">
<tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="680" cellpadding="0" cellspacing="0" style="max-width:680px;width:100%;background:#ffffff;border:1px solid {LINE}">
<tr><td style="background:#071525;padding:18px 28px">
  <div style="font:bold 20px/1.2 {FONT};color:#ffffff;letter-spacing:.06em">AEGIS</div>
  <div style="font:12px/1.4 {FONT};color:#7fb2ff;letter-spacing:.08em">CYBER SOLUTIONS · THREATWATCH</div>
</td></tr>
<tr><td style="padding:26px 28px 8px">
  <div style="font:bold 20px/1.3 {FONT};color:{NAVY}">{html.escape(title)}</div>
  <div style="font:14px/1.5 {FONT};color:{MUTED};margin-top:6px">{html.escape(rep.get("dateLabel", day))} · {html.escape(rep.get("window", ""))}</div>
  <div style="margin:16px 0 4px"><a href="{html.escape(web, quote=True)}" style="display:inline-block;background:{BLUE};color:#ffffff;text-decoration:none;font:bold 14px/1 {FONT};padding:11px 18px;border-radius:4px">Read the brief on the web</a></div>
  <div style="font:13px/1.5 {FONT};color:{MUTED};margin-top:8px">The website version is updated at 12:00, 5:00 and 10:00 PM ET with fresh data.</div>
</td></tr>
<tr><td style="padding:0 28px 8px">{sections}</td></tr>
<tr><td style="padding:6px 28px 20px">
  <h2 style="margin:18px 0 8px;font:bold 16px/1.3 {FONT};color:{NAVY}">References</h2>
  <ol style="margin:0;padding-left:20px;font:13px/1.5 {FONT};color:{INK}">{refs}</ol>
  <p style="font:12px/1.5 {FONT};color:{MUTED};margin:14px 0 0">{_inline(rep.get("sourceNote", ""))}</p>
</td></tr>
<tr><td style="background:#f5f7fa;border-top:1px solid {LINE};padding:16px 28px;font:12px/1.6 {FONT};color:{MUTED}">
  You are receiving this because you subscribed to the AEGIS ThreatWatch daily brief at aegisdefensecyber.com.<br>
  <a href="{UNSUBSCRIBE_TAG}" style="color:{BLUE}">Unsubscribe</a> ·
  <a href="{SITE_URL}/" style="color:{BLUE}">aegisdefensecyber.com</a> ·
  <a href="mailto:info@aegisdefensecyber.com" style="color:{BLUE}">info@aegisdefensecyber.com</a><br>
  {identity_footer_html(BLUE)}
</td></tr>
</table></td></tr></table>
</body></html>
"""
    return subject, page


def write_digest(brief: dict) -> Path:
    subject, page = render(brief)
    EMAIL_DIR.mkdir(parents=True, exist_ok=True)
    path = EMAIL_DIR / f"{brief['edition']}.html"
    path.write_text(page, encoding="utf-8")
    meta = {"edition": brief["edition"], "subject": subject,
            "path": f"threatwatch/email/{brief['edition']}.html"}
    (EMAIL_DIR / "latest.json").write_text(__import__("json").dumps(meta, indent=1, ensure_ascii=False) + "\n",
                                           encoding="utf-8")
    for old in sorted(EMAIL_DIR.glob("????-??-??.html"), reverse=True)[KEEP:]:
        old.unlink()
    print(f"Email page written: {meta['path']} — {subject}")
    return path


def main() -> int:
    brief = read_json(DATA_DIR / "latest.json")
    if not brief or not brief.get("report"):
        print("No published edition with a brief document.", file=sys.stderr)
        return 1
    write_digest(brief)
    return 0


if __name__ == "__main__":
    sys.exit(main())
