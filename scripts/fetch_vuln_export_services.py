#!/usr/bin/env python3
"""Build observed_services.json from the supported /vulns/export endpoint.

Replaces the deprecated Workbench Export (removed 2027-02-01) per Tenable's
migration guidance: /vulns/export returns vulnerability records that carry
asset + port {port, protocol, service} + plugin — exactly the observed-services
data correlate.py --services needs.

  python3 fetch_vuln_export_services.py --from-mcp tenable-one
  python3 fetch_vuln_export_services.py --from-mcp <inst> --max-chunks 20 --out output/observed_services.json

Keys via --from-mcp (X-ApiKeys from the MCP server entry in ~/.claude.json,
read in-process, never printed) or env TIO_ACCESS_KEY/TIO_SECRET_KEY.
Stdlib only. TLS trusts the Netskope CA when present.
"""
import argparse, json, os, ssl, sys, time, urllib.request, urllib.error

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


def make_opener(apikeys):
    ctx = ssl.create_default_context(cafile=CAFILE if os.path.exists(CAFILE) else None)
    def req(method, path, body=None):
        r = urllib.request.Request(BASE + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json", "X-ApiKeys": apikeys,
                     "Accept": "application/json"}, method=method)
        return urllib.request.urlopen(r, timeout=180, context=ctx)
    return req


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-mcp")
    ap.add_argument("--access-key"); ap.add_argument("--secret-key")
    ap.add_argument("--num-assets", type=int, default=5000,
                    help="asset scope for the export (default 5000)")
    ap.add_argument("--chunk-size", type=int, default=1000,
                    help="(format note: the API sets chunk size; kept for compatibility)")
    ap.add_argument("--max-chunks", type=int, default=50)
    ap.add_argument("--out", default=os.path.join("output", "observed_services.json"))
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

    req = make_opener(apikeys)
    try:
        r = json.load(req("POST", "/vulns/export",
                          {"num_assets": a.num_assets}))
    except urllib.error.HTTPError as e:
        sys.exit(f"/vulns/export request failed HTTP {e.code}: {e.read().decode()[:200]}")
    export_uuid = r.get("export_uuid") or r.get("uuid")
    if not export_uuid:
        sys.exit(f"no export_uuid in response: {json.dumps(r)[:200]}")
    print(f"export started: {export_uuid}")

    st = {}
    for _ in range(600):
        st = json.load(req("GET", f"/vulns/export/{export_uuid}/status"))
        if st.get("status") in ("FINISHED", "ERROR", "CANCELLED"):
            break
        time.sleep(3)
    print(f"status: {st.get('status')}, chunks: {len(st.get('chunks_available') or [])}")
    if st.get("status") != "FINISHED":
        sys.exit(f"export did not finish: {st.get('status')}")

    by_host = {}
    n_records = 0
    chunks = (st.get("chunks_available") or [])[:a.max_chunks]
    for cid in chunks:
        try:
            chunk = json.load(req("GET", f"/vulns/export/{export_uuid}/chunks/{cid}"))
        except urllib.error.HTTPError as e:
            print(f"  chunk {cid}: HTTP {e.code}")
            continue
        for rec in chunk:
            asset = rec.get("asset") or {}
            port = rec.get("port") or {}
            plugin = rec.get("plugin") or {}
            p = port.get("port")
            if not p:
                continue
            names = {n.lower() for n in (asset.get("name"), asset.get("hostname"),
                                         asset.get("fqdn")) if n}
            for ip in (asset.get("ipv4") or []):
                names.add(ip.lower())
            for key in names:
                by_host.setdefault(key, []).append({
                    "port": int(p),
                    "proto": port.get("protocol") or "tcp",
                    "svc": port.get("service") or "",
                    "plugin": int(plugin.get("id") or 0),
                    "pname": plugin.get("name") or ""})
            n_records += 1
        print(f"  chunk {cid}: {len(chunk)} records")

    out = os.path.expanduser(a.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    meta = {"source": f"/vulns/export ({len(chunks)} chunks, {n_records:,} vuln records)",
            "hosts": len(by_host), "items": n_records, "export_uuid": export_uuid}
    json.dump({"by_host": by_host, "meta": meta}, open(out, "w"))
    print(f"wrote {out}: {len(by_host)} hosts, {n_records:,} service records from /vulns/export")


if __name__ == "__main__":
    main()
