#!/usr/bin/env python3
"""Export recent completed VM scans and build observed_services.json.

Uses the VM scan-export API (POST /scans/{id}/export → poll → download) for
each completed scan within the window, saves the .nessus files, and parses
them with parse_vm_services.py into the observed-services index used by
correlate.py --services.

  python3 fetch_scan_services.py --from-mcp tenable-one --days 30
  python3 fetch_scan_services.py --from-mcp tenable-one --scan-ids 26,9

Keys via --from-mcp (X-ApiKeys from ~/.claude.json, in-process, never printed)
or env TIO_ACCESS_KEY/TIO_SECRET_KEY. TLS trusts the Netskope CA when present.
"""
import argparse, json, os, subprocess, sys, time, urllib.request, urllib.error, ssl

CAFILE = "/Library/Application Support/Netskope/STAgent/data/nscacert_combined.pem"
BASE = "https://cloud.tenable.com"
SKILL = os.path.dirname(os.path.abspath(__file__))


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


def req(method, path, body, apikeys, ctx):
    r = urllib.request.Request(BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "X-ApiKeys": apikeys,
                 "Accept": "application/json"}, method=method)
    return urllib.request.urlopen(r, timeout=180, context=ctx)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-mcp")
    ap.add_argument("--access-key"); ap.add_argument("--secret-key")
    ap.add_argument("--days", type=int, default=30, help="export scans completed within this many days")
    ap.add_argument("--scan-ids", help="comma list of scan ids (overrides --days)")
    ap.add_argument("--max-scans", type=int, default=8, help="cap on scans to export")
    ap.add_argument("--workdir", default="output")
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

    workdir = os.path.expanduser(a.workdir)
    scdir = os.path.join(workdir, "vm_scans")
    os.makedirs(scdir, exist_ok=True)
    ctx = ssl.create_default_context(cafile=CAFILE if os.path.exists(CAFILE) else None)

    if a.scan_ids:
        scan_ids = [int(s) for s in a.scan_ids.split(",") if s.strip()]
    else:
        cutoff = time.time() - a.days * 86400
        scans = json.load(req("GET", "/scans?limit=200", None, apikeys, ctx)).get("scans", [])
        scan_ids = []
        for s in scans:
            lm = s.get("last_modification_date") or 0
            if s.get("status") == "completed" and lm >= cutoff:
                scan_ids.append(s["id"])
                print(f"  candidate: scan {s['id']} '{s.get('name')}' (completed {time.strftime('%Y-%m-%d', time.gmtime(lm))})")
        scan_ids = scan_ids[:a.max_scans]
    if not scan_ids:
        sys.exit("no completed scans in the window — pass --scan-ids or widen --days")

    files = []
    for sid in scan_ids:
        out_file = os.path.join(scdir, f"scan_{sid}.nessus")
        if os.path.exists(out_file) and os.path.getsize(out_file) > 1000:
            print(f"  scan {sid}: already exported ({os.path.getsize(out_file):,} bytes)")
            files.append(out_file)
            continue
        try:
            t0 = json.load(req("POST", f"/scans/{sid}/export",
                               {"format": "nessus"}, apikeys, ctx))
            print(f"  scan {sid}: export response keys: {sorted(t0.keys())}")
            token = t0.get("token") or t0.get("file") and t0.get("token")
            if not token and t0.get("file"):
                # some tenants return {"file": "<name>"} immediately — the file id
                # to poll/download is derived from it; try token = file
                token = t0.get("file")
        except urllib.error.HTTPError as e:
            print(f"  scan {sid}: export failed HTTP {e.code} ({e.read().decode()[:120]})")
            continue
        if not token:
            print(f"  scan {sid}: no token in export response: {json.dumps(t0)[:200]}")
            continue
        for _ in range(120):
            st = json.load(req("GET", f"/scans/{sid}/export/{token}/status", None, apikeys, ctx))
            if st.get("status") == "ready":
                break
            time.sleep(3)
        else:
            print(f"  scan {sid}: export timed out")
            continue
        data = None
        for ep in (f"/scans/{sid}/export/{token}/download",
                   f"/scans/{sid}/export/{token}",
                   f"/scans/{sid}/export/{token}?download=1"):
            try:
                data = req("GET", ep, None, apikeys, ctx).read()
                break
            except urllib.error.HTTPError as e:
                print(f"    GET {ep.rsplit('/', 1)[-1] or ep} -> HTTP {e.code}")
                if e.code in (401, 403):
                    break  # auth issue: no point trying more endpoints
                continue
            except Exception as e:
                print(f"    GET {ep} -> {e}")
                continue
        if data:
            open(out_file, "wb").write(data)
            files.append(out_file)
            print(f"  scan {sid}: exported {len(data):,} bytes -> {out_file}")
        else:
            print(f"  scan {sid}: download failed (see attempts above)")

    if not files:
        sys.exit("no exports succeeded")
    print(f"\nparsing {len(files)} export(s)...")
    parse = os.path.join(SKILL, "parse_vm_services.py")
    r = subprocess.run([sys.executable, parse, *files,
                        "--out", os.path.join(workdir, "observed_services.json")],
                       capture_output=True, text=True)
    print(r.stdout.strip())
    if r.returncode:
        print(r.stderr.strip())


if __name__ == "__main__":
    main()
