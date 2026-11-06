#!/usr/bin/env python3
"""Enrich observed_services.json with asset names, using the Tenable One inventory.

The VM scans that produce service data often run uncredentialed (by IP), so the
index is keyed by IP while attack-path hops reference hostnames. This script
maps every IP key to its inventory asset name(s) via the exact-match
`ipv4_addresses contains` filter and merges the service records under each name.

  python3 enrich_service_names.py --from-mcp tenable-one
  python3 enrich_service_names.py --services output/observed_services.json --from-mcp tenable-one

Keys via --from-mcp (in-process, never printed) or env keys.
"""
import argparse, ipaddress, json, os, sys, urllib.request, urllib.error, ssl

CAFILE = "/Library/Application Support/Netskope/STAgent/data/nscacert_combined.pem"
BASE = "https://cloud.tenable.com"


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-mcp")
    ap.add_argument("--access-key"); ap.add_argument("--secret-key")
    ap.add_argument("--services", default=os.path.join("output", "observed_services.json"))
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
            sys.exit("provide --from-mcp, --access-key/--secret-key, or env keys")

    path = os.path.expanduser(a.services)
    svc = json.load(open(path))
    by_host = svc["by_host"]

    ip_keys = [k for k in by_host if _is_ip(k)]
    name_keys = [k for k in by_host if not _is_ip(k)]
    print(f"index: {len(ip_keys)} IP-only keys, {len(name_keys)} already named")

    ctx = ssl.create_default_context(cafile=CAFILE if os.path.exists(CAFILE) else None)
    mapped = 0
    for ip in ip_keys:
        try:
            r = post("/api/v1/t1/inventory/assets/search",
                     {"filters": [{"property": "ipv4_addresses", "operator": "contains",
                                   "value": [ip]}], "limit": 5}, apikeys, ctx)
        except urllib.error.HTTPError as e:
            print(f"  {ip}: query failed HTTP {e.code}")
            continue
        assets = (r.get("data") or [])
        if not assets:
            continue
        for asset in assets:
            nm = (asset.get("asset_name") or "").lower()
            if not nm or nm == ip.lower():
                continue
            for rec in by_host[ip]:
                by_host.setdefault(nm, []).append(rec)
        mapped += 1
        names = [a.get("asset_name") for a in assets[:3] if a.get("asset_name")]
        print(f"  {ip} -> {', '.join(names) if names else '(unnamed asset)'}")

    svc["meta"] = {**svc.get("meta", {}),
                   "name_mapped_ips": mapped,
                   "source": svc.get("meta", {}).get("source", "VM scan export") + " (names via inventory ipv4 lookup)"}
    json.dump(svc, open(path, "w"))
    print(f"done: {mapped} IP keys mapped; index now has {len(by_host)} keys")


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    main()
