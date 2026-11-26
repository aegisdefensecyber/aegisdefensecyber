import json, urllib.request, time
UA = {"User-Agent": "AegisThreatWatch/1.0 probe", "Accept": "application/json"}
def get(u):
    t = time.time()
    try:
        with urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=60) as r:
            return r.status, json.loads(r.read(30_000_000)), dict(r.headers), round(time.time() - t, 1)
    except Exception as e:
        return None, str(e)[:200], {}, round(time.time() - t, 1)
B = "https://vulnerability.circl.lu/api"
tests = [
  "/vulnerability/?source=certfr_avis&per_page=2",
  "/vulnerability/?source=certfr_avis&per_page=2&since=2026-11-01",
  "/vulnerability/?source=certfr_avis&per_page=2&light=false&since=2026-11-01",
  "/vulnerability/?sources=certfr_avis&per_page=2",
  "/vulnerability/last/certfr_avis/2",
  "/vulnerability/recent/2026-11-20/certfr_avis/2",
  "/vulnerability/?source=osv_ubuntu&per_page=2&since=2026-11-20",
  "/vulnerability/?source=github&per_page=2&since=2026-11-20",
  "/vulnerability/?source=csaf_microsoft&per_page=2&since=2026-11-20",
  "/vulnerability/?source=jvndb&per_page=2&since=2026-11-01",
  "/vulnerability/?source=variot&per_page=2&since=2026-11-01",
  "/vulnerability/?source=cvelistv5&per_page=2&since=2026-11-24",
  "/vulnerability/?source=debian_tracker&per_page=2&since=2026-11-20",
]
for t in tests:
    st, d, h, sec = get(B + t)
    print("=" * 100); print(t, "->", st, f"{sec}s", {k: v for k, v in h.items() if k.lower().startswith(("x-", "link", "ratelimit"))})
    if isinstance(d, list):
        print("LIST len", len(d))
        for r in d[:2]:
            print(json.dumps(r)[:1500]); print("-" * 40)
    elif isinstance(d, dict):
        print("DICT keys", list(d)[:20]); print(json.dumps(d)[:2500])
    else:
        print(d)
for t in ["/vulnerability/?source=certfr_avis&per_page=100&since=2026-08-27", "/vulnerability/?source=github&per_page=100&since=2026-11-24"]:
    st, d, h, sec = get(B + t)
    print("=" * 100); print("COUNT", t, st, sec, len(d) if isinstance(d, list) else (list(d)[:10] if isinstance(d, dict) else d))
