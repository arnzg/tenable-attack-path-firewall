#!/usr/bin/env python3
"""Parse a VM .nessus export into observed_services.json for correlate.py --services.

Reads ReportItems (host, port, protocol, service, plugin) and builds a
lowercased by-host index so attack-path hops can resolve their exploit's
observed port on the target.

  python3 parse_vm_services.py ~/Downloads/scan.nessus --out output/observed_services.json

Stdlib only. No API access — feed it any .nessus file (a scan export from
`fetch_scan_services.py`, a manual Nessus scan, or any other .nessus export;
the Workbench Export endpoint is deprecated and removed 2027-02-01 — do not
rely on it).
"""
import argparse, json, os, re, sys
import xml.etree.ElementTree as ET


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("nessus_files", nargs="+", help=".nessus file(s) to parse")
    ap.add_argument("--out", default=os.path.join("output", "observed_services.json"))
    a = ap.parse_args()

    by_host = {}
    n_items = 0
    for path in a.nessus_files:
        p = os.path.expanduser(path)
        if not os.path.exists(p):
            sys.exit(f"file not found: {p}")
        root = ET.parse(p).getroot()
        for rh in root.iter("ReportHost"):
            name = (rh.get("name") or "").strip()
            if not name:
                continue
            keys = {name.lower()}
            props = {}
            hp = rh.find("HostProperties")
            if hp is not None:
                for tag in hp.findall("tag"):
                    props[tag.get("name", "").lower()] = (tag.text or "").strip()
            for k in ("hostname", "host-ip"):
                v = props.get(k)
                if v:
                    keys.add(v.lower())
            for ri in rh.findall("ReportItem"):
                port = int(ri.get("port") or 0)
                if not port:
                    continue
                rec = {"port": port,
                       "proto": ri.get("protocol") or "tcp",
                       "svc": ri.get("svc_name") or "",
                       "plugin": int(ri.get("pluginID") or 0),
                       "pname": ri.get("pluginName") or ""}
                for key in keys:
                    if key:
                        by_host.setdefault(key, []).append(rec)
                n_items += 1

    out = os.path.expanduser(a.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    meta = {"source": os.path.basename(p) if len(a.nessus_files) == 1
            else f"{len(a.nessus_files)} VM scan exports",
            "hosts": len(by_host), "items": n_items}
    json.dump({"by_host": by_host, "meta": meta}, open(out, "w"))
    print(f"wrote {out}: {len(by_host)} hosts, {n_items} service records from {meta['source']}")


if __name__ == "__main__":
    main()
