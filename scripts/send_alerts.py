#!/usr/bin/env python3
"""Email significant watchlist alerts (critical / high) to subscribers who opted in to alerts.

Two steps around the commit in the publish workflow:
  --render  writes threatwatch/email/alert-<stamp>.html for significant alerts not yet emailed
            (and threatwatch/email/alerts-pending.json). Runs before the commit so the page goes live.
  --send    waits for that page to be live, then sends it through Zoho Campaigns to the alert
            audience: ZOHO_ALERTS_LIST_KEY; or, with ZOHO_ALERTS_SEGMENT_ID set, the daily-brief list; or the
            Zoho list named ZOHO_ALERTS_LIST_NAME (default "ThreatWatch Alerts"); optionally narrowed by ZOHO_ALERTS_SEGMENT_ID (the segment
            of the daily-brief list whose "ThreatWatch alerts" field is Yes). Not configured = no email.
Alert emails are batched per update (four times a day) and never resend an alert.
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_digest as BD  # noqa: E402
import send_digest as SD  # noqa: E402
from tw.common import DATA_DIR, ET, read_json, write_json  # noqa: E402

W = DATA_DIR / "watch"
EMAIL_DIR = BD.EMAIL_DIR
SIGNIFICANT = ("critical", "high")
MAX_AGE_H = 24          # never email an alert older than this (e.g. right after email is first enabled)


DEFAULT_ALERTS_LIST = "ThreatWatch Alerts"


def alerts_list_key(campaigns: str, token: str) -> str:
    """Which Zoho list receives alert emails, in order of preference:
    1. ZOHO_ALERTS_LIST_KEY;
    2. with ZOHO_ALERTS_SEGMENT_ID set, the daily-brief list (the segment narrows it to subscribers who
       ticked "ThreatWatch alerts" on the signup form);
    3. the list named ZOHO_ALERTS_LIST_NAME (default "ThreatWatch Alerts").
    Empty string when none applies, so alerts are never sent to the whole daily-brief list by accident."""
    if SD._env("ZOHO_ALERTS_LIST_KEY"):
        return SD._env("ZOHO_ALERTS_LIST_KEY")
    if SD._env("ZOHO_ALERTS_SEGMENT_ID"):
        return SD.list_key(campaigns, token)
    name = SD._env("ZOHO_ALERTS_LIST_NAME", DEFAULT_ALERTS_LIST).strip().lower()
    raw = SD._request(f"{campaigns}/api/v1.1/getmailinglists?resfmt=JSON&range=200",
                      headers={"Authorization": f"Zoho-oauthtoken {token}"})
    for lst in SD._zoho_ok(raw, "getmailinglists").get("list_of_details") or []:
        if str(lst.get("listname", "")).strip().lower() == name:
            return str(lst["listkey"])
    return ""


def esc(s) -> str:
    return html.escape(str(s or ""), quote=True)


def pending(now: datetime) -> list[dict]:
    state = read_json(W / "email-state.json", {}) or {}
    sent = set(state.get("sent") or [])
    cutoff = (now - timedelta(hours=MAX_AGE_H)).strftime("%Y-%m-%dT%H:%M:%SZ")
    evs = (read_json(W / "alerts.json", {}) or {}).get("events") or []
    return [e for e in evs if e["level"] in SIGNIFICANT and e["id"] not in sent and e["ts"] >= cutoff]


def render(events: list[dict], now: datetime) -> tuple[str, str, str]:
    stamp = now.strftime("%Y%m%d%H%M")
    crit = sum(1 for e in events if e["level"] == "critical")
    subject = (f"AEGIS alert: {crit} critical" if crit else f"AEGIS alert: {len(events)} significant") + \
              f" update{'s' if len(events) != 1 else ''} for your watched technology"
    NAVY, INK, MUTED, LINE, FONT, BLUE = BD.NAVY, BD.INK, BD.MUTED, BD.LINE, BD.FONT, BD.BLUE
    color = {"critical": "#b42318", "high": "#b54708"}
    rows = ""
    for e in sorted(events, key=lambda e: (e["level"] != "critical", e["watchName"])):
        link = next((l["u"] for l in e.get("links") or [] if l.get("u")), f"{BD.SITE_URL}/threatwatch/alerts.html")
        rows += (f'<tr><td style="padding:12px 0;border-bottom:1px solid {LINE}">'
                 f'<div style="font:bold 11px/1.3 {FONT};color:{color.get(e["level"], NAVY)};letter-spacing:.06em">'
                 f'{esc(e["level"].upper())} · {esc(e["watchName"])}</div>'
                 f'<div style="font:bold 15px/1.4 {FONT};color:{INK};margin:4px 0"><a href="{esc(link)}" style="color:{INK}">{esc(e["title"])}</a></div>'
                 f'<div style="font:14px/1.5 {FONT};color:{INK}">{esc(e.get("plain"))}</div>'
                 f'<div style="font:12px/1.5 {FONT};color:{MUTED};margin-top:3px">{esc(e["detail"])}</div></td></tr>')
    when = now.astimezone(ET).strftime("%B %-d, %Y, %-I:%M %p ET")
    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{esc(subject)}</title><meta name="robots" content="noindex"></head><body style="margin:0;background:#f4f6f8">
<!-- tw-alert:{stamp} -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;background:#ffffff;border:1px solid {LINE}">
<tr><td style="background:{NAVY};padding:18px 28px;font:bold 18px/1.3 {FONT};color:#ffffff">AEGIS ThreatWatch · Watchlist alert</td></tr>
<tr><td style="padding:20px 28px 4px;font:14px/1.5 {FONT};color:{MUTED}">{esc(when)} · {len(events)} significant change{'s' if len(events) != 1 else ''} in technology AEGIS monitors.
Critical = confirmed exploitation or a CISA KEV addition. High = public exploit code, a jump in exploitation likelihood, or an exploited vendor advisory.</td></tr>
<tr><td style="padding:4px 28px 8px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0">{rows}</table></td></tr>
<tr><td style="padding:12px 28px 24px;font:13px/1.5 {FONT};color:{MUTED}">All alerts, per-technology RSS feeds and analyst briefings:
<a href="{BD.SITE_URL}/threatwatch/alerts.html" style="color:{BLUE}">aegisdefensecyber.com/threatwatch/alerts.html</a>.
Reports are evidence, not proof that a specific system is affected; confirm against the vendor advisory before acting.<br><br>
You receive this because you chose daily brief + alerts. <a href="{BD.UNSUBSCRIBE_TAG}" style="color:{MUTED}">Unsubscribe</a></td></tr>
</table></td></tr></table></body></html>
"""
    return stamp, subject, page


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--render", action="store_true")
    ap.add_argument("--send", action="store_true")
    args = ap.parse_args()
    now = datetime.now(timezone.utc)
    if args.render:
        evs = pending(now)
        if not evs:
            write_json(EMAIL_DIR / "alerts-pending.json", {"pending": False})
            print("No new significant alerts to email.")
            return 0
        stamp, subject, page = render(evs, now)
        EMAIL_DIR.mkdir(parents=True, exist_ok=True)
        (EMAIL_DIR / f"alert-{stamp}.html").write_text(page, encoding="utf-8")
        for old in sorted(EMAIL_DIR.glob("alert-*.html"))[:-30]:   # keep the last 30 alert emails online
            old.unlink()
        write_json(EMAIL_DIR / "alerts-pending.json", {"pending": True, "stamp": stamp, "subject": subject,
                                                       "path": f"threatwatch/email/alert-{stamp}.html", "ids": [e["id"] for e in evs]})
        print(f"Alert email page written for {len(evs)} alert(s): {subject}")
        return 0
    if args.send:
        p = read_json(EMAIL_DIR / "alerts-pending.json", {}) or {}
        if not p.get("pending"):
            print("No alert email pending.")
            return 0
        missing = [n for n in SD.REQUIRED if not SD._env(n)] + ([] if SD.sender()[0] else ["ZOHO_FROM_EMAIL"])
        if missing:
            print(f"Alert email not configured (missing {', '.join(missing)}); alerts remain on the website and RSS.")
            return 0
        try:
            accounts = SD._https(SD._env("ZOHO_ACCOUNTS_URL", "https://accounts.zoho.com"), "ZOHO_ACCOUNTS_URL")
            campaigns = SD._https(SD._env("ZOHO_CAMPAIGNS_URL", "https://campaigns.zoho.com"), "ZOHO_CAMPAIGNS_URL")
            token = SD.access_token(accounts)
            list_key = alerts_list_key(campaigns, token)
            if not list_key:
                print(f"Alert email not configured: no ZOHO_ALERTS_LIST_KEY and no Zoho mailing list named "
                      f"{SD._env('ZOHO_ALERTS_LIST_NAME', DEFAULT_ALERTS_LIST)!r}; alerts remain on the website and RSS.")
                return 0
            url = f"{BD.SITE_URL}/{p['path']}"
            SD.wait_until_live(url, p["stamp"], marker=f"tw-alert:{p['stamp']}")
            seg = SD._env("ZOHO_ALERTS_SEGMENT_ID")
            auth = {"Authorization": f"Zoho-oauthtoken {token}"}
            params = {"resfmt": "JSON", "campaignname": f"ThreatWatch alert {p['stamp']}", "from_email": SD.sender()[0],
                      "from_name": SD.sender()[1], "subject": p["subject"], "content_url": url,
                      "list_details": json.dumps({list_key: [seg] if seg else []})}
            if SD._env("ZOHO_TOPIC_ID"):
                params["topicId"] = SD._env("ZOHO_TOPIC_ID")
            doc = SD._zoho_ok(SD._request(f"{campaigns}/api/v1.1/createCampaign", params, auth), "createCampaign")
            key = str(doc.get("campaignKey") or doc.get("campaignkey") or "")
            SD._zoho_ok(SD._request(f"{campaigns}/api/v1.1/sendcampaign", {"resfmt": "JSON", "campaignkey": key}, auth), "sendcampaign")
        except Exception as exc:  # noqa: BLE001
            print(f"ALERT EMAIL NOT SENT: {exc}", file=sys.stderr)
            return 1
        st = read_json(W / "email-state.json", {}) or {}
        st["sent"] = (list(p["ids"]) + list(st.get("sent") or []))[:5000]
        st["lastSentAt"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        write_json(W / "email-state.json", st)
        write_json(EMAIL_DIR / "alerts-pending.json", {"pending": False, "lastSent": p["stamp"]})
        print(f"Alert email {p['stamp']} sent (campaign {key}).")
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
