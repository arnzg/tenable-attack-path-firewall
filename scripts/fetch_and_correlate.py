#!/usr/bin/env python3
"""One-command pipeline: fetch APA topology -> extract hops -> correlate ->
build dashboard.

  python3 fetch_and_correlate.py --from-mcp tenable-one
  python3 fetch_and_correlate.py --rules my_rulebase.json --workdir ./run
  python3 fetch_and_correlate.py --from-mcp tenable-one --quick

Keys via --from-mcp (reads X-ApiKeys from the MCP server entry in
~/.claude.json, in-process, never printed), env TIO_ACCESS_KEY/TIO_SECRET_KEY,
or --access-key/--secret-key. TLS trusts the Netskope CA when present.
Page size is >=100 (API rejects smaller).
"""
import json, os, argparse, collections, re, urllib.request, urllib.error, ssl, sys

SKILL = os.path.dirname(os.path.abspath(__file__))
CAFILE = "/Library/Application Support/Netskope/STAgent/data/nscacert_combined.pem"
BASE = "https://cloud.tenable.com"
NET_TECH = {
    "Remote Desktop Protocol": ("tcp", [3389]),
    "Windows Remote Management": ("tcp", [5985, 5986]),
    "SMB/Windows Admin Shares": ("tcp", [445]),
    "Services Registry Permissions Weakness": ("tcp", [445]),
    "Services File Permissions Weakness": ("tcp", [445]),
    "Windows Management Instrumentation": ("tcp", [135]),
    "Distributed Component Object Model": ("tcp", [135]),
    "DCSync": ("tcp", [135, 49152]),
    "Domain Controller Authentication": ("tcp", [88, 464]),
    "Domain Accounts": ("tcp", [88, 464]),
    "Scheduled Task": ("tcp", [135]),
}
PORT_BY_HINT = {p: ("tcp", [int(p)]) for p in
                ("3389", "445", "5985", "135", "22", "80", "443", "1433", "3306")}


def resolve_keys(args):
    if args.access_key and args.secret_key:
        return f"accessKey={args.access_key}; secretKey={args.secret_key}"
    ak, sk = os.environ.get("TIO_ACCESS_KEY"), os.environ.get("TIO_SECRET_KEY")
    if ak and sk:
        return f"accessKey={ak}; secretKey={sk}"
    if args.from_mcp:
        d = json.load(open(os.path.expanduser("~/.claude.json")))

        def walk(node):
            if isinstance(node, dict):
                ms = node.get("mcpServers")
                if isinstance(ms, dict) and args.from_mcp in ms:
                    h = (ms[args.from_mcp] or {}).get("headers") or {}
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
        k = walk(d)
        if k:
            return k
        sys.exit(f"--from-mcp '{args.from_mcp}' not found in ~/.claude.json")
    sys.exit("No API keys. Use --access-key/--secret-key, env TIO_ACCESS_KEY/TIO_SECRET_KEY, or --from-mcp.")


def fetch_paths(apikeys, limit_page, max_paths):
    paths, offset = [], 0
    ctx = ssl.create_default_context(cafile=CAFILE if os.path.exists(CAFILE) else None)
    while True:
        req = urllib.request.Request(
            f"{BASE}/api/v1/t1/apa/top-attack-paths/search?limit={limit_page}&offset={offset}&exclude_resolved=true",
            data=b"{}", headers={"Content-Type": "application/json",
                                 "X-ApiKeys": apikeys, "Accept": "application/json"})
        try:
            r = urllib.request.urlopen(req, timeout=120, context=ctx)
        except urllib.error.HTTPError as e:
            sys.exit(f"HTTP {e.code}: {e.read().decode()[:300]}")
        batch = json.load(r).get("data", [])
        if not batch:
            break
        paths.extend(batch)
        print(f"  fetched offset={offset} -> {len(batch)} (cumulative {len(paths)})")
        if len(batch) < limit_page or len(paths) >= max_paths:
            break
        offset += limit_page
    return paths


def tech_info(tname):
    base = tname.rsplit("-", 1)[0]
    for fam, info in NET_TECH.items():
        if base == fam or base.startswith(fam):
            return info
    m = re.search(r"-(\d{2,5})(?::(\d{2,5}))?$", tname)
    if base.startswith("Exploitation of Remote Services"):
        if m and m.group(2) in PORT_BY_HINT:
            return PORT_BY_HINT[m.group(2)]
        return ("tcp", [0])
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-mcp")
    ap.add_argument("--access-key"); ap.add_argument("--secret-key")
    ap.add_argument("--rules", help="rulebase JSON (default: bundled simulator rules)")
    ap.add_argument("--edr-map", help="edr_map.json from build_edr_map.py (or written from MCP queries) — real EDR presence from 3rd-party connector sources")
    ap.add_argument("--services", help="observed_services.json (from parse_vm_services.py) — refines unknown-port exploit hops with the target's scan evidence")
    ap.add_argument("--workdir", default="output")
    ap.add_argument("--out")
    ap.add_argument("--instance", default="tenable")
    ap.add_argument("--quick", action="store_true", help="top 1,000 paths only")
    a = ap.parse_args()

    workdir = os.path.expanduser(a.workdir)
    os.makedirs(workdir, exist_ok=True)
    rules_path = os.path.expanduser(a.rules) if a.rules else \
        os.path.join(SKILL, "..", "simulator", "fortigate_lab_rules.json")

    print("1/4 fetching attack-path topology...")
    paths = fetch_paths(resolve_keys(a), 1000, 1000 if a.quick else 30000)
    json.dump(paths, open(os.path.join(workdir, f"apa_paths_{a.instance}.json"), "w"))
    print(f"   {len(paths)} paths")

    print("2/4 extracting network hops...")
    hops, devices = [], {}
    for p in paths:
        prio, id2n = p.get("priority"), {n.get("id"): n for n in (p.get("nodes") or [])}
        for n in (p.get("nodes") or []):
            if any(l in (n.get("labels") or []) for l in
                   ("Computer", "WindowsServer", "WindowsWorkstation", "WebApplication")):
                devices.setdefault(n.get("name"), {"labels": n.get("labels"),
                                                   "asset_id": n.get("asset_id")})
        for t in (p.get("techniques") or []):
            info = tech_info(t.get("name", ""))
            if not info:
                continue
            pair = t.get("nodes") or []
            if len(pair) != 2:
                continue
            src, dst = id2n.get(pair[0]), id2n.get(pair[1])
            if not src or not dst:
                continue
            hops.append({"path_priority": prio, "vector_id": p.get("vector_id"),
                         "src": src.get("name"), "src_labels": src.get("labels"),
                         "dst": dst.get("name"), "dst_labels": dst.get("labels"),
                         "technique": t.get("name"), "proto": info[0], "ports": info[1]})
    json.dump(hops, open(os.path.join(workdir, f"apa_hops_{a.instance}.json"), "w"))
    json.dump(devices, open(os.path.join(workdir, f"apa_devices_{a.instance}.json"), "w"))
    print(f"   {len(hops)} hops, {len(devices)} devices")

    print("3/4 correlating against the rulebase...")
    sys.path.insert(0, os.path.join(SKILL, "scripts"))
    import correlate
    # reuse correlate.main's full logic (evaluation, EDR, services, what-if) on files
    paths_file = os.path.join(workdir, f"apa_paths_{a.instance}.json")
    hops_file = os.path.join(workdir, f"apa_hops_{a.instance}.json")
    corr_file = os.path.join(workdir, f"correlation_{a.instance}.json")
    extra = []
    if a.edr_map:
        extra += ["--edr-map", os.path.expanduser(a.edr_map)]
    if a.services:
        extra += ["--services", os.path.expanduser(a.services)]
    sys.argv = ["correlate", "--paths", paths_file, "--hops", hops_file,
                "--rules", rules_path, "--out", corr_file] + extra
    correlate.main()

    print("4/4 building dashboard...")
    import build_dashboard
    out = a.out or os.path.join(workdir, f"firewall-paths-dashboard-{a.instance}.html")
    sys.argv = ["build_dashboard", "--corr", corr_file, "--out", out,
                "--instance", a.instance]
    build_dashboard.main()
    print(f"\nDone. Dashboard: {out}")


if __name__ == "__main__":
    main()
