import json, urllib.request, time
UA = {"User-Agent": "AegisThreatWatch/1.0 (+https://aegisdefensecyber.com/threatwatch/)", "Accept": "application/json"}
def get(u):
    with urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=60) as r:
        return json.loads(r.read(30_000_000))
def shape(o, d=0, maxd=4):
    if d > maxd: return "…"
    if isinstance(o, dict): return {k: shape(v, d+1, maxd) for k, v in list(o.items())[:40]}
    if isinstance(o, list): return [shape(o[0], d+1, maxd)] if o else []
    if isinstance(o, str): return o[:70]
    return o
B = "https://vulnerability.circl.lu/api/vulnerability/?per_page=1&source="
for s in ["certfr_avis", "certfr_alerte", "jvndb", "debian_tracker", "csaf_cisco", "csaf_ncscnl", "alpine", "bitnami_vulndb", "drupal", "tailscale", "cisa_known_exploited", "avid", "csaf_certbund"]:
    try:
        d = get(B + s); time.sleep(3.2)
        print("=" * 30, s); print(json.dumps(shape(d[0] if d else None), ensure_ascii=False)[:3500])
    except Exception as e:
        print("=" * 30, s, "ERR", e)
