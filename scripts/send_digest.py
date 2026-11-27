#!/usr/bin/env python3
"""Send the morning ThreatWatch brief to subscribers through Zoho Campaigns.

Called by the publish workflow only when a NEW edition was published (the 7:00 AM
slot); the 12:00, 17:00 and 22:00 updates never email. Steps:

  1. wait until the email page (threatwatch/email/<edition>.html) is live on the site,
  2. exchange the Zoho refresh token for an access token,
  3. create a campaign whose content is that page (content_url) for the mailing list,
  4. send it.

Zoho Campaigns keeps the subscriber list, double opt-in and unsubscribes; this
repository never stores an email address. If the Zoho secrets are not set the
script prints a notice and exits 0, so publishing is never blocked by email.

Environment (GitHub → Settings → Secrets and variables → Actions):
  ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET, ZOHO_REFRESH_TOKEN   secrets (Self Client in api-console.zoho.com)
  ZOHO_LIST_KEY       optional: mailing list key; if unset the list is looked up by name
  ZOHO_LIST_NAME      optional, default "ThreatWatch Daily Brief"
  ZOHO_FROM_EMAIL                                          verified sender, e.g. info@aegisdefensecyber.com
  ZOHO_FROM_NAME      optional, default "AEGIS ThreatWatch"
  ZOHO_TOPIC_ID       optional, only for accounts using Zoho topic management
  ZOHO_ACCOUNTS_URL   optional, default https://accounts.zoho.com  (EU: https://accounts.zoho.eu, …)
  ZOHO_CAMPAIGNS_URL  optional, default https://campaigns.zoho.com (EU: https://campaigns.zoho.eu, …)

Usage:
  python scripts/send_digest.py            # send today's morning brief
  python scripts/send_digest.py --dry-run  # check configuration and the live page, send nothing
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_digest import EMAIL_DIR, SITE_URL  # noqa: E402
from tw.common import DATA_DIR, read_json  # noqa: E402

REQUIRED = ("ZOHO_CLIENT_ID", "ZOHO_CLIENT_SECRET", "ZOHO_REFRESH_TOKEN")
CONFIG = Path(__file__).resolve().parent.parent / "threatwatch" / "subscription-config.json"


def sender() -> tuple[str, str]:
    """Sender address and name: threatwatch/subscription-config.json wins, then the env variables."""
    try:
        cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cfg = {}
    return (str(cfg.get("fromEmail") or _env("ZOHO_FROM_EMAIL")),
            str(cfg.get("fromName") or _env("ZOHO_FROM_NAME", "AEGIS ThreatWatch")))
DEFAULT_LIST = "ThreatWatch Daily Brief"
UA = "aegis-threatwatch-digest/1.0"


class DigestError(Exception):
    pass


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _https(url: str, name: str) -> str:
    if not url.startswith("https://") or any(c in url for c in " \"'<>"):
        raise DigestError(f"{name} must be an https URL")
    return url.rstrip("/")


def _request(url: str, data: dict | None = None, headers: dict | None = None, timeout: int = 30) -> str:
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"User-Agent": UA, **(headers or {})},
                                 method="POST" if body is not None else "GET")
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def wait_until_live(url: str, edition: str, attempts: int = 45, delay: int = 20, marker: str | None = None) -> None:
    """GitHub Pages deploys a minute or two after the commit; Zoho must fetch the new page."""
    marker = marker or f"tw-edition:{edition}"
    for i in range(attempts):
        try:
            if marker in _request(f"{url}?v={int(time.time())}"):
                return
        except (urllib.error.URLError, TimeoutError):
            pass
        if i < attempts - 1:
            time.sleep(delay)
    raise DigestError(f"email page for {edition} not live at {url} after {attempts * delay // 60} minutes")


def access_token(accounts: str) -> str:
    raw = _request(f"{accounts}/oauth/v2/token", {
        "refresh_token": _env("ZOHO_REFRESH_TOKEN"), "client_id": _env("ZOHO_CLIENT_ID"),
        "client_secret": _env("ZOHO_CLIENT_SECRET"), "grant_type": "refresh_token"})
    tok = json.loads(raw).get("access_token")
    if not tok:
        raise DigestError(f"Zoho token refresh failed: {json.loads(raw).get('error', 'no access_token')}")
    return tok


def _zoho_ok(raw: str, what: str) -> dict:
    try:
        doc = json.loads(raw)
    except ValueError:
        raise DigestError(f"{what}: unexpected response from Zoho") from None
    if str(doc.get("code")) not in ("200", "0") and doc.get("status") != "success":
        raise DigestError(f"{what} failed: {doc.get('message') or doc.get('code')}")
    return doc


def list_key(campaigns: str, token: str) -> str:
    if _env("ZOHO_LIST_KEY"):
        return _env("ZOHO_LIST_KEY")
    name = _env("ZOHO_LIST_NAME", DEFAULT_LIST)
    raw = _request(f"{campaigns}/api/v1.1/getmailinglists?resfmt=JSON&range=200",
                   headers={"Authorization": f"Zoho-oauthtoken {token}"})
    doc = _zoho_ok(raw, "getmailinglists")
    for lst in doc.get("list_of_details") or []:
        if str(lst.get("listname", "")).strip().lower() == name.lower():
            return str(lst["listkey"])
    raise DigestError(f"mailing list {name!r} not found in Zoho Campaigns")


def create_and_send(campaigns: str, token: str, edition: str, subject: str, content_url: str) -> str:
    auth = {"Authorization": f"Zoho-oauthtoken {token}"}
    params = {
        "resfmt": "JSON",
        "campaignname": f"ThreatWatch {edition}",
        "from_email": sender()[0],
        "from_name": sender()[1],
        "subject": subject,
        "content_url": content_url,
        "list_details": json.dumps({list_key(campaigns, token): []}),
    }
    if _env("ZOHO_TOPIC_ID"):
        params["topicId"] = _env("ZOHO_TOPIC_ID")
    doc = _zoho_ok(_request(f"{campaigns}/api/v1.1/createCampaign", params, auth), "createCampaign")
    key = str(doc.get("campaignKey") or doc.get("campaignkey") or "")
    if not key:
        raise DigestError("createCampaign returned no campaign key")
    _zoho_ok(_request(f"{campaigns}/api/v1.1/sendcampaign", {"resfmt": "JSON", "campaignkey": key}, auth),
             "sendcampaign")
    return key


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    missing = [n for n in REQUIRED if not _env(n)] + ([] if sender()[0] else ["ZOHO_FROM_EMAIL"])
    if missing:
        print(f"Email digest not configured (missing {', '.join(missing)}); nothing sent.")
        return 0
    meta = read_json(EMAIL_DIR / "latest.json", {}) or {}
    latest = read_json(DATA_DIR / "latest.json", {}) or {}
    edition = meta.get("edition")
    if not edition or edition != latest.get("edition"):
        print(f"No email page for the current edition ({latest.get('edition')}); nothing sent.", file=sys.stderr)
        return 1
    try:
        accounts = _https(_env("ZOHO_ACCOUNTS_URL", "https://accounts.zoho.com"), "ZOHO_ACCOUNTS_URL")
        campaigns = _https(_env("ZOHO_CAMPAIGNS_URL", "https://campaigns.zoho.com"), "ZOHO_CAMPAIGNS_URL")
        content_url = f"{SITE_URL}/{meta['path']}"
        wait_until_live(content_url, edition)
        token = access_token(accounts)
        if args.dry_run:
            key = list_key(campaigns, token)
            print(f"Dry run OK: page live at {content_url}; Zoho token works; list key {key[:6]}…; nothing sent.")
            return 0
        key = create_and_send(campaigns, token, edition, meta["subject"], content_url)
    except (DigestError, urllib.error.URLError, TimeoutError, ValueError, KeyError) as exc:
        print(f"EMAIL NOT SENT: {exc}", file=sys.stderr)
        return 1
    print(f"Morning brief {edition} sent through Zoho Campaigns (campaign {key}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
