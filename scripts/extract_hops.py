#!/usr/bin/env python3
"""Extract network-relevant hops + device inventory from the APA dump.

Outputs:
  output/apa_hops.json        - network-applicable hops: {path_prio, src, dst, tech}
  output/apa_devices.json     - device-ish nodes with names/labels
Prints summary stats. No credentials involved.
"""
import json, os, collections, re, argparse

ap = argparse.ArgumentParser()
ap.add_argument("--paths", default="output/apa_paths.json")
ap.add_argument("--out", default="output/apa_hops.json")
a = ap.parse_args()

DIR = os.path.dirname(os.path.expanduser(a.out))
paths = json.load(open(os.path.expanduser(a.paths)))

# technique family -> (protocol, ports) heuristic; None = not network-applicable
NET_TECH = {
    "Remote Desktop Protocol": ("tcp", [3389]),
    "Windows Remote Management": ("tcp", [5985, 5986]),
    "SMB/Windows Admin Shares": ("tcp", [445]),
    "Windows Management Instrumentation": ("tcp", [135]),
    "Distributed Component Object Model": ("tcp", [135]),
    "DCSync": ("tcp", [135, 49152]),
    "Domain Controller Authentication": ("tcp", [88, 464]),
    "Domain Accounts": ("tcp", [88, 464]),
    "Scheduled Task": ("tcp", [135]),
    "Services Registry Permissions Weakness": ("tcp", [445]),
    "Services File Permissions Weakness": ("tcp", [445]),
}
PORT_BY_HINT = {
    "3389": ("tcp", [3389]), "445": ("tcp", [445]), "5985": ("tcp", [5985]),
    "135": ("tcp", [135]), "22": ("tcp", [22]), "80": ("tcp", [80]),
    "443": ("tcp", [443]), "1433": ("tcp", [1433]), "3306": ("tcp", [3306]),
}

def tech_info(tname):
    base = tname.rsplit("-", 1)[0]
    for fam, info in NET_TECH.items():
        if base == fam or base.startswith(fam):
            return info
    m = re.search(r"-(\d{2,5})(?::(\d{2,5}))?$", tname)
    if base.startswith("Exploitation of Remote Services"):
        if m and m.group(2) and m.group(2) in PORT_BY_HINT:
            return PORT_BY_HINT[m.group(2)]
        return ("tcp", [0])   # network hop, port unknown
    return None

hops, devices, subs = [], {}, collections.Counter()
dev_reachable = collections.Counter()
net_paths = 0
for p in paths:
    prio = p.get("priority")
    nodes = p.get("nodes") or []
    id2n = {n.get("id"): n for n in nodes}
    has_net = False
    for n in nodes:
        lbs = n.get("labels") or []
        if any(l in lbs for l in ("Computer", "WindowsServer", "WindowsWorkstation",
                                  "WebApplication", "MacWorkstation", "Unix")):
            key = n.get("name")
            if key and key not in devices:
                devices[key] = {"labels": lbs, "asset_id": n.get("asset_id")}
        if "Subnet" in lbs:
            subs[n.get("name")] += 1
    for t in p.get("techniques") or []:
        info = tech_info(t.get("name", ""))
        if not info:
            continue
        pair = t.get("nodes") or []
        if len(pair) != 2:
            continue
        src, dst = id2n.get(pair[0]), id2n.get(pair[1])
        if not src or not dst:
            continue
        has_net = True
        hops.append({"path_priority": prio, "vector_id": p.get("vector_id"),
                     "src": src.get("name"), "src_labels": src.get("labels"),
                     "dst": dst.get("name"), "dst_labels": dst.get("labels"),
                     "technique": t.get("name"), "proto": info[0], "ports": info[1]})
        for label in ("DomainController",):
            if label in (dst.get("labels") or []):
                dev_reachable[dst.get("name")] += 1
    if has_net:
        net_paths += 1

json.dump(hops, open(os.path.expanduser(a.out), "w"))
json.dump(devices, open(os.path.join(DIR, "apa_devices.json"), "w"))

print(f"paths total: {len(paths)} | paths w/ network hops: {net_paths}")
print(f"network hops: {len(hops)} | distinct device nodes: {len(devices)} | subnet nodes: {len(subs)}")

hop_tech = collections.Counter(h["technique"].rsplit("-", 1)[0] for h in hops)
print("\nNETWORK HOPS BY TECHNIQUE:")
for t, c in hop_tech.most_common(15):
    print(f"  {c:6d}  {t}")

pair = collections.Counter((h["src"], h["dst"]) for h in hops)
print("\nTOP DEVICE->DEVICE HOPS:")
for (s, d), c in pair.most_common(20):
    print(f"  {c:6d}  {s}  ->  {d}")

dc = collections.Counter(h["dst"] for h in hops if "DomainController" in (h["dst_labels"] or []))
print("\nTOP DC TARGETS:")
for d, c in dc.most_common(10):
    print(f"  {c:6d}  {d}")

print("\nSUBNET NODES (top):")
for s, c in subs.most_common(10):
    print(f"  {c:6d}  {s}")

print("\nSAMPLE DEVICE NAMES:")
for i, (nm, meta) in enumerate(devices.items()):
    if i >= 30: break
    print(f"  {nm}  labels={meta['labels']}")
