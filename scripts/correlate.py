#!/usr/bin/env python3
"""Firewall-Aware Attack Path Correlation Engine.

Evaluates each network-relevant attack-path hop against a normalized firewall
rulebase (FortiGate semantics: top-down, first match wins, default deny).

Inputs:
  --paths   apa_paths_*.json   full APA path dump
  --hops    apa_hops.json      network-relevant hops (from extract_hops.py)
  --rules   fortigate rulebase (lab JSON today; vendor MCP export later)
  --out     correlation.json

Verdicts:
  ALLOWED / DENIED / IMPLICIT (default deny) / UNVERIFIED (unknown port,
  no broad rule matches) / NO_ZONES (endpoint unmapped) / NO_NETWORK (identity hop)
"""
import json, os, argparse, collections, ipaddress, fnmatch, zlib

def edr_for(name, zone, rules, edr_map=None):
    """EDR vendor for an endpoint, or None.

    Production: edr_map is {lowercased name/asset_id: vendor} built from real
    3rd-party connector sources. When a map is supplied it is AUTHORITATIVE —
    endpoints not in it have no EDR (we never mix real data with the simulated
    zone model). Only without a map does the simulated zone_coverage apply.
    """
    if edr_map is not None:
        return edr_map.get((name or "").lower())
    cov = (rules.get("edr_coverage") or {}).get("zone_coverage") or {}
    zc = cov.get(zone)
    if not zc:
        return None
    import zlib as _z
    threshold = float(zc.get("coverage", 0)) * 100.0
    if (_z.crc32((name or "").lower().encode()) % 100) < threshold:
        return zc.get("vendor")
    return None

def load(p):
    with open(os.path.expanduser(p)) as f:
        return json.load(f)

def zone_for(node_name, labels, rules):
    """Resolve a node (by name + labels) to a firewall zone."""
    n = (node_name or "").lower()
    labels = set(labels or [])
    DEVICE_LB = {"Computer", "WindowsServer", "WindowsWorkstation", "WebApplication",
                 "MacWorkstation", "Subnet", "Internet", "DomainController"}
    if "Internet" in labels:
        return "external"
    # user accounts originate from user space (checked before the identity gate:
    # a user carries a Domain label but is not an identity-only node)
    if "User" in labels and not (labels & DEVICE_LB):
        return "users"
    # identity-only nodes (no device/component markers): not routed by a firewall
    if (labels & {"Group", "Domain", "Forest", "ActiveDirectory"}) and not \
       (labels & DEVICE_LB):
        return None
    if "DomainController" in labels:
        return "core"
    for r in rules["asset_zone_rules"]:
        if r["match"] == "name_suffix":
            if n in [x.lower() for x in r["names"]]:
                return r["zone"]
        elif r["match"] == "domain_controller":
            if n in [x.lower() for x in r["names"]]:
                return r["zone"]
        elif r["match"] == "suffix_re":
            import re
            if any(re.search(s.lower(), n) for s in r["suffixes"]):
                return r["zone"]
        elif r["match"] == "subnet":
            try:
                net = ipaddress.ip_network(n, strict=False)
                if net.subnet_of(ipaddress.ip_network(r["cidr"])):
                    return r["zone"]
            except ValueError:
                pass
    # generic label fallbacks
    if "Subnet" in labels:
        try:
            net = ipaddress.ip_network(n, strict=False)
            for r in rules["asset_zone_rules"]:
                if r["match"] == "subnet" and net.subnet_of(ipaddress.ip_network(r["cidr"])):
                    return r["zone"]
        except ValueError:
            pass
    if "WindowsServer" in labels or "WebApplication" in labels:
        return "servers"
    if "WindowsWorkstation" in labels or "MacWorkstation" in labels:
        return "users"
    # default zone for genuinely unmapped endpoints (cloud subnets, unknown VPCs)
    for r in rules["asset_zone_rules"]:
        if r["match"] == "default":
            return r["zone"]
    return None

def addr_matches(endpoint_name, zone, addr_names, rules):
    """Does any policy srcaddr/dstaddr entry cover this endpoint?

    A "<zone>-all" group covers every endpoint in that zone (FortiGate-style:
    a subnet/zone object covers all traffic sourced from it, including
    identity-originated hops mapped to that zone).
    """
    n = (endpoint_name or "").lower()
    for a in addr_names:
        al = a.lower()
        if al == "any":
            return True
        if al == f"{zone}-all":
            return True
        if n == al:
            return True
        if al in rules.get("address_groups", {}):
            for m in _expand(al, rules):
                if m.lower() == n:
                    return True
        try:
            ipaddress.ip_network(n, strict=False).subnet_of(ipaddress.ip_network(al, strict=False))
            return True
        except ValueError:
            pass
    return False

def _expand(gname, rules, seen=None):
    seen = seen or set()
    if gname in seen: return []
    seen.add(gname)
    out = []
    for m in rules.get("address_groups", {}).get(gname, []):
        out += _expand(m, rules, seen) if m in rules.get("address_groups", {}) else [m]
    return out

def service_covers(services, proto, ports, rules):
    """Do any of the policy's services cover the (proto, ports) of the hop?"""
    svc = {s["name"].lower(): s for s in rules["services"]}
    for name in services:
        s = svc.get(name.lower())
        if not s:
            if name.lower() == "all":
                return True
            continue
        if s["protocol"] != "any" and proto != "any" and s["protocol"] != proto:
            continue
        if 0 in s["ports"]:
            return True
        if any(p in s["ports"] for p in ports):
            return True
    return False

def match_policy(sz, dz, src, dst, proto, ports, rules, policies):
    """First-match-wins evaluation for concrete (proto, ports). None if no policy matches."""
    for pol in policies:
        if not pol.get("status", True):
            continue
        if sz not in pol["srcintf"] or dz not in pol["dstintf"]:
            continue
        if not addr_matches(src, sz, pol["srcaddr"], rules):
            continue
        if not addr_matches(dst, dz, pol["dstaddr"], rules):
            continue
        if not service_covers(pol["service"], proto, ports, rules):
            continue
        return {"verdict": "ALLOWED" if pol["action"] == "allow" else "DENIED",
                "src_zone": sz, "dst_zone": dz,
                "rule_id": pol["id"], "rule_name": pol["name"]}
    return None


def policy_ports(pol, rules):
    """Expand a policy's service names to (protocol, port) tuples."""
    svc = {s["name"].lower(): s for s in rules["services"]}
    out = []
    for name in pol["service"]:
        s = svc.get(name.lower())
        if not s:
            continue
        for p in s["ports"]:
            if p:
                out.append((s["protocol"], p))
    return out


def resolve_observed_ports(dst, sz, dz, dst_zone_addr, pids, services, rules, policies):
    """Ports observed on the target that an exploit hop could use.

    Order of evidence (strongest first):
      1. plugin match: the VM scan that detected this technique recorded its port
      2. any target port that the zone pair's allow policies would permit
    Returns (ports, evidence) or (None, None).
    """
    if services is None:
        return None, None
    obs = services.get((dst or "").lower())
    if not obs:
        return None, None
    pids = set(pids or [])
    if pids:
        by_plugin = [r["port"] for r in obs if r.get("port") and r.get("plugin") in pids]
        if by_plugin:
            return sorted(set(by_plugin)), f"observed port from scan plugin ({', '.join(str(p) for p in sorted(set(by_plugin)))})"
    allowed = set()
    for pol in policies:
        if pol.get("action") != "allow" or not pol.get("status", True):
            continue
        if sz not in pol["srcintf"] or dz not in pol["dstintf"]:
            continue
        if not addr_matches(dst, dz, pol["dstaddr"], rules):
            continue
        for _, p in policy_ports(pol, rules):
            allowed.add(p)
    observed = {r["port"] for r in obs if r.get("port")}
    both = sorted(allowed & observed)
    if both:
        return both, "ports the policy allows and the target is listening on"
    return None, None


def evaluate_hop(hop, rules, policies, pids=None, services=None):
    DEVICE = {"Computer", "WindowsServer", "WindowsWorkstation", "WebApplication",
              "MacWorkstation", "Subnet", "Internet", "DomainController"}
    IDENTITY = {"Group", "Domain", "Forest", "ActiveDirectory", "ScheduledTask"}
    src_l, dst_l = set(hop.get("src_labels") or []), set(hop.get("dst_labels") or [])
    def identity_only(lb):
        return bool(lb & IDENTITY) and not bool(lb & DEVICE) and "User" not in lb
    if identity_only(src_l) or identity_only(dst_l):
        return {"verdict": "NO_NETWORK", "src_zone": None, "dst_zone": None}
    sz = zone_for(hop["src"], hop.get("src_labels"), rules)
    dz = zone_for(hop["dst"], hop.get("dst_labels"), rules)
    if sz is None or dz is None:
        return {"verdict": "NO_ZONES", "src_zone": sz, "dst_zone": dz}
    proto, ports = hop["proto"], hop["ports"]
    unknown_port = ports == [0]
    candidate_allows = []       # specific-service allow rules that COULD carry this hop
    for pol in policies:
        if not pol.get("status", True):
            continue
        if sz not in pol["srcintf"] or dz not in pol["dstintf"]:
            continue
        if not addr_matches(hop["src"], sz, pol["srcaddr"], rules):
            continue
        if not addr_matches(hop["dst"], dz, pol["dstaddr"], rules):
            continue
        covers = service_covers(pol["service"], proto, ports, rules)
        if unknown_port:
            # only an ALL-service rule can give a named verdict for an unknown port
            if "ALL" in [s.upper() for s in pol["service"]]:
                v = {"verdict": "ALLOWED" if pol["action"] == "allow" else "DENIED",
                     "src_zone": sz, "dst_zone": dz,
                     "rule_id": pol["id"], "rule_name": pol["name"]}
                v["port_evidence"] = "ALL-service rule"
                return v
            if pol["action"] == "allow":
                candidate_allows.append(pol)
            continue
        if not covers:
            continue
        return {"verdict": "ALLOWED" if pol["action"] == "allow" else "DENIED",
                "src_zone": sz, "dst_zone": dz,
                "rule_id": pol["id"], "rule_name": pol["name"]}
    if unknown_port:
        resolved, evidence = resolve_observed_ports(hop["dst"], sz, dz, hop["dst"],
                                                    pids, services, rules, policies)
        if resolved:
            verdicts = []
            for port in resolved:
                m = match_policy(sz, dz, hop["src"], hop["dst"], proto, [port], rules, policies)
                if m is None:
                    verdicts.append({"port": port, "verdict": "IMPLICIT"})
                else:
                    verdicts.append({"port": port, **m})
            live = [v for v in verdicts if v["verdict"] == "ALLOWED"]
            v = (live[0] if live else verdicts[-1])
            v["observed_ports"] = resolved
            v["port_evidence"] = evidence
            return v
        if candidate_allows:
            r = {"verdict": "UNVERIFIED", "src_zone": sz, "dst_zone": dz,
                 "would_allow": [p["name"] for p in candidate_allows]}
            obs = services.get((hop["dst"] or "").lower()) if services else None
            if obs:
                r["dst_observed_ports"] = sorted({o["port"] for o in obs if o.get("port")})
            return r
        if rules.get("default_deny", True):
            return {"verdict": "IMPLICIT", "src_zone": sz, "dst_zone": dz}
        return {"verdict": "ALLOWED", "src_zone": sz, "dst_zone": dz}
    if rules.get("default_deny", True):
        return {"verdict": "IMPLICIT", "src_zone": sz, "dst_zone": dz}
    return {"verdict": "ALLOWED", "src_zone": sz, "dst_zone": dz}  # permissive default

def evaluate_all_hops(hops, rules, policies, edr_map=None, tech_plugins=None, services=None):
    """Evaluate every hop in place (mutates hop dicts: verdict/rule/edr fields)."""
    for h in hops:
        pids = (tech_plugins or {}).get(h["vector_id"], {}).get(h["technique"])
        v = evaluate_hop(h, rules, policies, pids=pids, services=services)
        v["edr_src"] = edr_for(h["src"], v.get("src_zone"), rules, edr_map)
        v["edr_dst"] = edr_for(h["dst"], v.get("dst_zone"), rules, edr_map)
        h.update(v)


def verdict_paths(hops, meta_by_vec=None, prio_by_vec=None):
    """Group hops per path and classify LIVE/BLOCKED/PARTIALLY_VERIFIED/UNMAPPED."""
    by_path = collections.defaultdict(list)
    for h in hops:
        if h["verdict"] == "NO_NETWORK":
            continue
        by_path[h["vector_id"]].append(h)
    pvs = []
    for vid, hs in by_path.items():
        verdicts = [h["verdict"] for h in hs]
        applicable = [v for v in verdicts if v != "NO_ZONES"]
        if not applicable:
            pv = "UNMAPPED"
        elif "DENIED" in applicable or "IMPLICIT" in applicable:
            pv = "BLOCKED"
        elif "UNVERIFIED" in applicable:
            pv = "PARTIALLY_VERIFIED"
        else:
            pv = "LIVE"
        pname = psummary = ptech = None
        if meta_by_vec:
            pname, psummary, ptech = meta_by_vec.get(vid, (None, None, []))
        pvs.append({
            "vector_id": vid,
            "priority": (prio_by_vec or {}).get(vid),
            "name": pname, "summary": psummary, "techniques": ptech,
            "verdict": pv, "hops": len(hs),
            "hop_verdicts": verdicts,
            "blocked_by": [h.get("rule_name", "default-deny") for h in hs
                           if h["verdict"] in ("DENIED", "IMPLICIT")],
            "paths_to_target": hs[-1]["dst"]})
    return by_path, pvs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--paths", default="output/apa_paths.json", help="APA path dump (from fetch_and_correlate.py)")
    ap.add_argument("--hops", default="output/apa_hops.json")
    ap.add_argument("--rules", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "simulator", "fortigate_lab_rules.json"))
    ap.add_argument("--out", default="output/correlation.json")
    ap.add_argument("--edr-map", help="JSON file mapping hostname/asset_id (lowercased) -> EDR vendor, "
                                      "built from the Tenable One inventory's 3rd-party connector sources "
                                      "(build_edr_map.py); when given, the map is authoritative — "
                                      "unmapped endpoints have no EDR (no simulated fallback)")
    ap.add_argument("--services", help="observed_services.json (from parse_vm_services.py on a VM scan "
                                       "export): observed listening ports per host. Refines unknown-port "
                                       "exploit hops into named ALLOWED/DENIED verdicts using the target's "
                                       "own scan evidence")
    a = ap.parse_args()

    rules = load(a.rules)
    hops = load(a.hops)
    paths = load(a.paths)
    prio_by_vec = {p["vector_id"]: p.get("priority") for p in paths
                   if isinstance(p.get("vector_id"), (int, str))}
    policies = rules["policies"]

    edr_map = None
    edr_meta = {"source": "simulated", "vendors": {}}
    if a.edr_map:
        raw = load(a.edr_map)
        if isinstance(raw, dict) and "by_hostname" in raw:
            edr_map = {**{k.lower(): v for k, v in raw.get("by_hostname", {}).items()},
                       **{k.lower(): v for k, v in raw.get("by_asset_id", {}).items()}}
            by_vendor = collections.Counter(raw.get("by_hostname", {}).values())
        else:  # legacy flat map
            edr_map = raw
            by_vendor = collections.Counter(raw.values())
        edr_meta = {"source": "real (3rd-party connector sources)", "vendors": dict(by_vendor)}
        for vendor, n in by_vendor.most_common():
            print(f"  edr source: {vendor} -> {n} assets")
        if not by_vendor:
            print("  WARNING: EDR map is empty — check vendor spellings and the sources filter "
                  "(exact match required; contains is ignored by the API)")

    services = None
    services_meta = {"source": "none (unknown-port hops stay UNVERIFIED)"}
    if a.services:
        svc_raw = load(a.services)
        services = svc_raw.get("by_host", {})
        _meta = svc_raw.get("meta", {})
        services_meta = {"source": _meta.get("source", "VM scan export"),
                         "hosts": len(services),
                         "services": _meta.get("items",
                                               sum(len(v) for v in services.values()))}
        print(f"  observed services: {services_meta['hosts']} hosts, "
              f"{services_meta['services']} service records")

    # plugin anchors must exist before hop evaluation (observed-port matching
    # resolves exploit ports via the scan plugin that detected the technique)
    tech_plugins = {}
    for p in paths:
        vid = p.get("vector_id")
        if not isinstance(vid, (int, str)):
            continue
        m = {}
        for t in (p.get("techniques") or []):
            try:
                si = json.loads(t.get("source_information") or "[]")
            except Exception:
                si = []
            pids = sorted({i.get("provider_detection_id") for i in si
                           if i.get("provider_code") == "NESSUS" and i.get("provider_detection_id")})
            if pids:
                m[t.get("name", "?")] = pids
        if m:
            tech_plugins[vid] = m
    json.dump(tech_plugins, open(os.path.expanduser(a.out).replace("correlation", "tech_plugins"), "w"))

    evaluate_all_hops(hops, rules, policies, edr_map=edr_map,
                      tech_plugins=tech_plugins, services=services)
    meta_by_vec = {p["vector_id"]: (p.get("name"), p.get("summary"),
                                    [t.get("name") for t in (p.get("techniques") or [])])
                   for p in paths if isinstance(p.get("vector_id"), (int, str))}

    by_path, path_verdicts = verdict_paths(hops, meta_by_vec, prio_by_vec)

    # scan coverage of attack-path targets (the actionable gap: unscanned targets)
    applicable = [h for h in hops if h["verdict"] not in ("NO_NETWORK", "NO_ZONES")]
    tgt_total = len({h["dst"] for h in applicable})
    svc_keys = set(services.keys()) if services else set()
    tgt_covered = len({h["dst"] for h in applicable if (h["dst"] or "").lower() in svc_keys})
    if services is not None:
        services_meta["targets_total"] = tgt_total
        services_meta["targets_covered"] = tgt_covered
        if tgt_total and tgt_covered < tgt_total:
            print(f"  WARNING: only {tgt_covered} of {tgt_total} attack-path targets have scan "
              "evidence — run a credentialed scan of the missing subnets to resolve their hops")


    # identity-only paths (no network-relevant technique at all): firewall can't help
    NET_FAMS = ("Remote Desktop Protocol", "Windows Remote Management",
                "SMB/Windows Admin Shares", "Services Registry Permissions Weakness",
                "Services File Permissions Weakness", "Windows Management Instrumentation",
                "Distributed Component Object Model", "DCSync",
                "Domain Controller Authentication", "Domain Accounts", "Scheduled Task",
                "Exploitation of Remote Services")
    id_stats = {"count": 0, "families": collections.Counter(), "targets": collections.Counter()}
    for p in paths:
        fams = {t.get("name", "").rsplit("-", 1)[0] for t in (p.get("techniques") or [])}
        if any(any(f.startswith(nf) for nf in NET_FAMS) for f in fams):
            continue
        id_stats["count"] += 1
        for f in fams:
            id_stats["families"][f] += 1
        tn = p.get("nodes") or []
        if tn:
            id_stats["targets"][tn[-1].get("name", "?")] += 1
    id_stats["families"] = dict(id_stats["families"].most_common(15))
    id_stats["targets"] = dict(id_stats["targets"].most_common(15))

    # ---- remediation what-if: simulate candidate policy changes ----
    import copy

    def path_counts(pvs):
        c = collections.Counter(p["verdict"] for p in pvs)
        return {k: c.get(k, 0) for k in ("LIVE", "PARTIALLY_VERIFIED", "BLOCKED", "UNMAPPED")}

    baseline_counts = path_counts(path_verdicts)
    pol_by_name = {p["name"]: p for p in policies}
    by_policy = collections.defaultdict(lambda: {"allowed": 0, "unverified": 0,
                                                 "pairs": set(), "svc_names": set()})
    svc_by_port = {}
    for s in rules["services"]:
        for port in s["ports"]:
            if port:
                svc_by_port[port] = s["name"]
    for h in hops:
        if h["verdict"] == "ALLOWED" and h.get("rule_name"):
            e = by_policy[h["rule_name"]]
            e["allowed"] += 1
            e["pairs"].add((h.get("src_zone"), h.get("dst_zone")))
            for port in h["ports"]:
                if port and port in svc_by_port:
                    e["svc_names"].add(svc_by_port[port])
        elif h["verdict"] == "UNVERIFIED":
            for name in h.get("would_allow") or []:
                by_policy[name]["unverified"] += 1
                by_policy[name]["pairs"].add((h.get("src_zone"), h.get("dst_zone")))

    ranked = sorted(by_policy.items(), key=lambda kv: -(kv[1]["allowed"] + kv[1]["unverified"]))[:6]
    scenarios = []
    for pname, e in ranked:
        pol = pol_by_name.get(pname)
        if not pol:
            continue
        before = baseline_counts
        if e["svc_names"] and e["allowed"]:
            change = (f'Add an explicit deny for {", ".join(sorted(e["svc_names"]))} from '
                      f'{", ".join(sorted({a for a, _ in e["pairs"] if a}))} to '
                      f'{", ".join(sorted({b for _, b in e["pairs"] if b}))} — '
                      f"the traffic rule {pname} currently permits")
            new_policies = copy.deepcopy(policies)
            deny_rule = {"id": -1,
                         "name": f"WhatIf-Deny-{'-'.join(sorted(e['svc_names']))}-{pname}",
                         "srcintf": pol["srcintf"], "dstintf": pol["dstintf"],
                         "srcaddr": pol["srcaddr"], "dstaddr": pol["dstaddr"],
                         "service": sorted(e["svc_names"]), "action": "deny",
                         "log": True, "status": True,
                         "comment": f"what-if: cut the paths rule {pname} carries"}
            idx = next(i for i, p in enumerate(new_policies) if p["name"] == pname)
            new_policies.insert(idx, deny_rule)
            scenario_type = "add_deny"
        else:
            change = f"Remove (or tighten) rule {pname} so it no longer permits this traffic"
            new_policies = [p for p in copy.deepcopy(policies) if p["name"] != pname]
            scenario_type = "remove_rule"
        hops_copy = copy.deepcopy(hops)
        evaluate_all_hops(hops_copy, rules, new_policies, edr_map=edr_map,
                          tech_plugins=tech_plugins, services=services)
        _, pvs_after = verdict_paths(hops_copy, meta_by_vec, prio_by_vec)
        after = path_counts(pvs_after)
        cut = [p for p in path_verdicts if p["verdict"] == "LIVE"]
        cut_after = {p["vector_id"] for p in pvs_after if p["verdict"] == "BLOCKED"}
        cut = [p for p in cut if p["vector_id"] in cut_after]
        cut.sort(key=lambda x: -(x.get("priority") or 0))
        scenarios.append({
            "name": f"Restrict {pname}", "rule": pname, "type": scenario_type,
            "change": change,
            "before": before, "after": after,
            "live_delta": after["LIVE"] - before["LIVE"],
            "possible_delta": after["PARTIALLY_VERIFIED"] - before["PARTIALLY_VERIFIED"],
            "blocked_delta": after["BLOCKED"] - before["BLOCKED"],
            "cut_live_paths": [{"name": p.get("name"), "priority": p.get("priority"),
                                "target": p["paths_to_target"]} for p in cut[:5]],
            "cut_live_total": len(cut),
        })

    out = {"engine": "firewall-aware attack path correlation v0.2",
           "rulebase": a.rules,
           "hops_total": len(hops),
           "hop_verdict_counts": dict(collections.Counter(h["verdict"] for h in hops)),
           "paths_with_network_hops": len(by_path),
           "path_verdict_counts": dict(collections.Counter(pv["verdict"] for pv in path_verdicts)),
           "hop_results": hops,
           "path_verdicts": path_verdicts,
           "identity_stats": id_stats,
           "edr_meta": edr_meta,
           "services_meta": services_meta,
           "whatif": {"baseline": baseline_counts, "scenarios": scenarios}}
    json.dump(out, open(os.path.expanduser(a.out), "w"))

    print(f"hops: {len(hops)}  -> {out['hop_verdict_counts']}")
    print(f"paths with network hops: {len(by_path)}  -> {out['path_verdict_counts']}")
    live = sorted([pv for pv in path_verdicts if pv["verdict"] == "LIVE"],
                  key=lambda x: -(x["priority"] or 0))[:10]
    print("\nTOP LIVE (surviving) PATHS by priority:")
    for pv in live:
        print(f"  prio={pv['priority']}  vec={pv['vector_id']}  hops={pv['hop_verdicts']}  -> {pv['paths_to_target']}")
    blocked = sorted([pv for pv in path_verdicts if pv["verdict"] == "BLOCKED"],
                     key=lambda x: -(x["priority"] or 0))[:5]
    print("\nTOP BLOCKED PATHS by priority (overstated risk):")
    for pv in blocked:
        print(f"  prio={pv['priority']}  vec={pv['vector_id']}  cut by {pv['blocked_by']}")

if __name__ == "__main__":
    main()
