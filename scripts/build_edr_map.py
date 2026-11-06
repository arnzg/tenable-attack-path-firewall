#!/usr/bin/env python3
"""Build an EDR presence map from Tenable One's 3rd-party connector sources.

For each configured EDR vendor, queries the inventory with exact-match
`sources = [vendor]` (verified: the `contains` operator is IGNORED by the API)
plus `asset_class = DEVICE`, paginated. Writes a JSON map of
hostname/asset_id (lowercased) -> vendor for correlate.py --edr-map.

  python3 build_edr_map.py --from-mcp tenable-demo-pod
  python3 build_edr_map.py --vendors "SentinelOne,CrowdStrike" --out edr_map.json

Keys via --from-mcp (X-ApiKeys from the MCP server entry in ~/.claude.json,
read in-process, never printed) or env TIO_ACCESS_KEY/TIO_SECRET_KEY.
"""
import argparse, json, os, sys, urllib.request, urllib.error, ssl

CAFILE = "/Library/Application Support/Netskope/STAgent/data/nscacert_combined.pem"
BASE = "https://cloud.tenable.com"

# Default: EDR vendors Tenable supports (provided by the user 2026-11-02).
# Spelling variants are probed automatically because the API matches the
# `sources` value exactly — e.g. "SentinelOne" (verified) vs "Sentinel One".
DEFAULT_VENDORS = [
    "Cortex XDR", "CrowdStrike", "Crowdstrike", "Jamf Pro", "Jamf pro",
    "Microsoft TVM", "Microsoft Defender for Endpoint", "Microsoft Defender",
    "Outpost 24", "Outpost24", "Rapid7 InsightVM", "Rapid7", "Rapid & insight",
    "SentinelOne", "Sentinel One", "Tanium", "Tanimum",
]


def find_keys(name):
    d = json.load(open(os.path.expanduser("~/.claude.json")))
    def walk(node):
        if isinstance(node, dict):
            ms = node.get("mcpServers")
            if isinstance(ms, dict) and name in ms:
                h = (ms[name] or {}).get("headers") or {}
                if h.get("X-ApiKeys"):
                    return h["X-ApiKeys"]
            for v in node.values():
                r = walk(v)
                if r: return r
        elif isinstance(node, list):
            for v in node:
                r = walk(v)
                if r: return r
        return None
    return walk(d)


def post(path, body, apikeys, ctx):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "X-ApiKeys": apikeys,
                 "Accept": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=120, context=ctx))


def search_assets(apikeys, ctx, vendor, limit=200):
    """Yield (asset_id, name) pages for a vendor's exact sources value."""
    filters = [{"property": "asset_class", "operator": "=", "value": ["DEVICE"]},
               {"property": "sources", "operator": "=", "value": [vendor]}]
    offset, seen = 0, 0
    while True:
        r = post("/api/v1/t1/inventory/assets/search",
                 {"filters": filters, "limit": limit, "offset": offset}, apikeys, ctx)
        batch = r.get("data") or []
        for a in batch:
            aid, nm = a.get("asset_id"), a.get("asset_name")
            if aid and nm:
                yield aid, nm
        seen += len(batch)
        if len(batch) < limit or seen > 20000:
            return
        offset += limit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-mcp")
    ap.add_argument("--access-key"); ap.add_argument("--secret-key")
    ap.add_argument("--vendors", help="comma-separated vendor names (default: Tenable-supported EDR list)")
    ap.add_argument("--out", default=os.path.join("output", "edr_map.json"))
    a = ap.parse_args()

    if a.access_key and a.secret_key:
        apikeys = f"accessKey={a.access_key}; secretKey={a.secret_key}"
    else:
        ak, sk = os.environ.get("TIO_ACCESS_KEY"), os.environ.get("TIO_SECRET_KEY")
        if ak and sk:
            apikeys = f"accessKey={ak}; secretKey={sk}"
        elif a.from_mcp:
            apikeys = find_keys(a.from_mcp)
            if not apikeys:
                sys.exit(f"no X-ApiKeys for MCP server '{a.from_mcp}'")
        else:
            sys.exit("provide --from-mcp, --access-key/--secret-key, or env TIO_ACCESS_KEY/TIO_SECRET_KEY")

    vendors = [v.strip() for v in a.vendors.split(",")] if a.vendors else DEFAULT_VENDORS
    ctx = ssl.create_default_context(cafile=CAFILE if os.path.exists(CAFILE) else None)

    amap, amap_ids = {}, {}
    matched = {}
    for vendor in vendors:
        if vendor in matched:
            continue  # a variant already matched; keep the first spelling that worked
        hits = list(search_assets(apikeys, ctx, vendor))
        if not hits:
            print(f"  {vendor}: 0 assets (no exact sources match)")
            continue
        matched[vendor] = len(hits)
        for aid, nm in hits:
            amap.setdefault(nm.lower(), vendor)
            amap_ids.setdefault(aid.lower(), vendor)
        print(f"  {vendor}: {len(hits)} assets")

    if not matched:
        print("WARNING: no EDR connector sources found — the map is empty. "
              "Check vendor spellings; the API matches `sources` exactly.")
    out = os.path.expanduser(a.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({**amap, **amap_ids}, open(out, "w"))
    total = len(set(amap.values()) | set(amap_ids.values()))
    print(f"wrote {out}: {len(amap)} hostnames + {len(amap_ids)} asset ids "
          f"across vendors {sorted(set(matched))}")


if __name__ == "__main__":
    main()
