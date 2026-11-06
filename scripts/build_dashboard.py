#!/usr/bin/env python3
"""Build the Firewall-Aware Attack Path Validation dashboard.

Reads output/correlation.json (+ paths meta for names/summaries) and writes a
single self-contained HTML file (Tenable brand, dark-first, offline).
Usage: python3 build_dashboard.py [--instance tenable-one] [--out file.html]
"""
import json, os, argparse, collections, datetime, html

DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(DIR, "output")

def load(p):
    with open(os.path.expanduser(p)) as f:
        return json.load(f)

def esc(s):
    return html.escape(str(s)) if s is not None else ""

ZONES = ["external", "dmz", "users", "apps", "servers", "core", "mgmt", "ot"]
VC = {"ALLOWED": ("good", "allowed"), "DENIED": ("bad", "denied"),
      "IMPLICIT": ("warn", "default-deny"), "UNVERIFIED": ("info", "may pass — port unverified"),
      "NO_ZONES": ("muted", "no zone"), "NO_NETWORK": ("muted", "identity"),
      "LIVE": ("bad", "live"), "BLOCKED": ("good", "blocked"),
      "UNMAPPED": ("muted", "unmapped"), "PARTIALLY_VERIFIED": ("warn", "partial")}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corr", default=os.path.join(OUT, "correlation.json"))
    ap.add_argument("--rules", default=os.path.join(DIR, "simulator", "fortigate_lab_rules.json"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--instance", default="tenable-one")
    ap.add_argument("--firewall-note", default="Simulated FortiGate (FGLAB-EDGE-01, FortiOS 7.4.5) rulebase — demonstration data")
    a = ap.parse_args()

    corr = load(a.corr)
    rules = load(a.rules) if os.path.exists(os.path.expanduser(a.rules)) else {}
    hops = corr["hop_results"]
    pvs = corr["path_verdicts"]
    hvc = corr["hop_verdict_counts"]
    pvc = corr["path_verdict_counts"]

    live = sorted([p for p in pvs if p["verdict"] == "LIVE"],
                  key=lambda x: -(x.get("priority") or 0))
    blocked = sorted([p for p in pvs if p["verdict"] == "BLOCKED"],
                     key=lambda x: -(x.get("priority") or 0))
    unmapped = [p for p in pvs if p["verdict"] == "UNMAPPED"]
    n_net = corr["paths_with_network_hops"]
    idstats = corr.get("identity_stats", {"count": 0, "families": {}, "targets": {}})
    total_paths = 24355

    # patch anchors: technique -> plugin ids, and plugin enrichment (optional)
    tp_file = a.corr.replace("correlation", "tech_plugins")
    tech_plugins = load(tp_file) if os.path.exists(os.path.expanduser(tp_file)) else {}
    enr_file = os.path.join(OUT, "plugin_enrichment.json")
    enrichment = load(enr_file) if os.path.exists(enr_file) else {}
    kev_file = os.path.join(OUT, "kev.json")
    kev_set = {}
    if os.path.exists(kev_file):
        kev_raw = load(kev_file)
        kev_set = {v["cveID"]: v.get("dateAdded") for v in kev_raw.get("vulnerabilities", [])}
    hops_by_vec = collections.defaultdict(list)
    for h in hops:
        hops_by_vec[h["vector_id"]].append(h)

    # ---- zone matrix ----
    matrix = collections.defaultdict(collections.Counter)
    for h in hops:
        sz, dz = h.get("src_zone"), h.get("dst_zone")
        if sz and dz and h["verdict"] in ("ALLOWED", "IMPLICIT", "DENIED", "UNVERIFIED"):
            matrix[(sz, dz)][h["verdict"]] += 1

    # ---- rule impact ----
    rule_impact = collections.defaultdict(lambda: collections.Counter())
    for h in hops:
        if h["verdict"] in ("ALLOWED", "IMPLICIT", "DENIED"):
            rid = h.get("rule_name", "default-deny (implicit)")
            rule_impact[rid][h["verdict"]] += 1
        elif h["verdict"] == "UNVERIFIED":
            for rid in (h.get("would_allow") or []):
                rule_impact[rid]["UNVERIFIED"] += 1
    rule_rows = sorted(rule_impact.items(), key=lambda kv: -sum(kv[1].values()))

    # ---- live path technique families ----
    live_tech = collections.Counter()
    for p in live:
        for t in p.get("techniques") or []:
            live_tech[t.rsplit("-", 1)[0]] += 1

    # top targets among live paths
    live_targets = collections.Counter(p["paths_to_target"] for p in live)

    now = datetime.date.today().isoformat()
    generated = f"{now} — instance {a.instance}"
    instance_lbl = a.instance

    # brand wordmark (chokepoint-style lime "tenable"; matches the skill family)
    logo_html = '<span class="brandfallback"><span class="brandword">tenable</span></span>'

    # ---------- helpers ----------
    def chip(verdict, n):
        tone, label = VC.get(verdict, ("muted", verdict.lower()))
        return f'<span class="chip {tone}" title="{esc(verdict)}">{n:,} {label}</span>'

    def hopchip(v):
        tone, label = VC.get(v, ("muted", v.lower()))
        return f'<span class="chip {tone}">{label}</span>'

    def tile(n, label, tone="", goto=None):
        g = f' data-goto="{esc(goto)}" role="button" tabindex="0"' if goto else ""
        return (f'<div class="tile {tone}"{g}><div class="tile-n">{n:,}</div>'
                f'<div class="tile-l">{esc(label)}</div></div>')

    # ---------- zone traffic flows ----------
    # one row per (src -> dst) zone pair carrying traffic; riskiest first
    flows = [(p, c) for p, c in matrix.items()
             if c["ALLOWED"] + c["IMPLICIT"] + c["DENIED"] + c["UNVERIFIED"] > 0]
    flows.sort(key=lambda pc: (-pc[1]["ALLOWED"], -pc[1]["UNVERIFIED"],
                               -(pc[1]["ALLOWED"] + pc[1]["IMPLICIT"] + pc[1]["DENIED"] + pc[1]["UNVERIFIED"])))

    # per-flow drill-down: attack paths whose hops traverse this zone pair
    flow_detail = collections.defaultdict(dict)   # (sz,dz) -> vector_id -> hop list
    for h in hops:
        sz, dz = h.get("src_zone"), h.get("dst_zone")
        if sz and dz and h["verdict"] in ("ALLOWED", "IMPLICIT", "DENIED", "UNVERIFIED"):
            flow_detail[(sz, dz)].setdefault(h["vector_id"], []).append(h)
    prio_by_vec_f = {p["vector_id"]: (p.get("priority"), p.get("name"), p.get("summary"))
                     for p in pvs}

    def flow_detail_html(pair):
        per_vec = flow_detail.get(pair, {})
        entries = []
        for vid, hs in per_vec.items():
            prio, name, summary = prio_by_vec_f.get(vid, (None, vid, ""))
            entries.append((prio or 0, vid, prio, name, summary, hs))
        n_all = sum(len(v) for v in per_vec.values())
        tools = (f'<div class="panel-tools">'
                 f'<button class="dlbtn" type="button" data-flowcsv="{esc(pair[0])}|{esc(pair[1])}">'
                 f'Download all {n_all:,} paths (CSV)</button>'
                 f'<span class="note">columns: priority, attack_path, technique, from, to, verdict, rule_reached, edr_on_target</span></div>')
        # collapse same-shaped paths (same name + technique families) into one row
        groups = collections.defaultdict(list)
        for e in entries:
            key = (str(e[3] or e[1]).casefold(),
                   tuple(sorted({(h["technique"] or "").rsplit("-", 1)[0].casefold() for h in e[5]})))
            groups[key].append(e)
        reps = [sorted(g, key=lambda e: (-e[0], -len(e[5])))[0] for g in groups.values()]
        reps.sort(key=lambda e: (-e[0], -len(e[5])))
        n_total = len(reps)
        rows = []
        for _, vid, prio, name, summary, hs in reps[:10]:
            gcount = len(groups[(str(name or vid).casefold(),
                                 tuple(sorted({(h["technique"] or "").rsplit("-", 1)[0].casefold() for h in hs})))] or [])
            badge = (f'<span class="chip">×{gcount:,}</span>' if gcount > 1 else "")
            live_hs = hs  # include all hops (implicit/deny paths matter too)
            tname = live_hs[0]["technique"].rsplit("-", 1)[0] + (f" (+{len(live_hs)-1} more hops)" if len(live_hs) > 1 else "")
            rules = []
            for h in live_hs:
                r = h.get("rule_name") or ", ".join(h.get("would_allow") or []) or "default-deny"
                if r not in rules:
                    rules.append(r)
            rows.append(
                f'<tr><td><span class="prio">{prio if prio is not None else "—"}</span></td>'
                f'<td>{esc(name or vid)} {badge}</td>'
                f"<td>{esc(tname)}</td><td>{esc(live_hs[-1]['dst'])}</td>"
                f"<td>{esc(' → '.join(rules))}</td>"
                f"<td>{esc(live_hs[-1].get('edr_dst') or 'none')}</td></tr>")
        more = (f'<p class="note">Showing 10 of {n_total:,} path shapes through this flow '
                f"({len(entries):,} paths total). Same-shaped paths are collapsed — the ×N badge counts them. "
                f"Use the CSV button for every path, one row per hop.</p>"
                if n_total > 10 else "")
        return (f'<div class="pdetails" hidden>{tools}{more}'
                '<div class="scrollx"><table class="table hops"><thead><tr>'
                "<th>Priority</th><th>Attack path</th><th>Technique</th><th>Reaches</th>"
                "<th>Rule reached</th><th>EDR on target</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></div>")

    frows = []
    for (sz, dz), c in flows:
        total = c["ALLOWED"] + c["IMPLICIT"] + c["DENIED"] + c["UNVERIFIED"]
        segs = []
        for v in ("ALLOWED", "UNVERIFIED", "IMPLICIT", "DENIED"):
            if c[v]:
                tone = {"ALLOWED": "seg-bad", "UNVERIFIED": "seg-info", "IMPLICIT": "seg-warn",
                        "DENIED": "seg-good"}[v]
                pct = 100.0 * c[v] / total
                segs.append(f'<div class="seg {tone}" style="width:{pct:.2f}%" '
                            f'title="{esc(v.lower())}: {c[v]:,} hops"></div>')
        bar = (f'<div class="flow-bar">{"".join(segs)}</div>'
               if segs else '<div class="flow-bar empty"></div>')
        chips = " ".join(chip(v, c[v]) for v in ("ALLOWED", "UNVERIFIED", "IMPLICIT", "DENIED") if c[v])
        if c["ALLOWED"] > 0:
            state = '<span class="flow-state bad">live exposure</span>'
        elif c["UNVERIFIED"] > 0:
            state = '<span class="flow-state warn">possible exposure — verify ports</span>'
        else:
            state = '<span class="flow-state good">fully segmented</span>'
        has_detail = True
        attrs = ' role="button" tabindex="0"'
        cls = "flow clickable"
        dtbtn = '<button class="dtbtn" type="button" aria-expanded="false">Details ▾</button>'
        get_through = c["ALLOWED"] + c["UNVERIFIED"]
        if get_through > 0:
            if c["ALLOWED"] and c["UNVERIFIED"]:
                stat = (f'<div class="flow-stat">{get_through:,} of {total:,} attack steps get through — '
                        f'{c["ALLOWED"]:,} confirmed, {c["UNVERIFIED"]:,} port-unverified</div>')
            elif c["UNVERIFIED"]:
                stat = (f'<div class="flow-stat">{get_through:,} of {total:,} attack steps may get through '
                        '(exploit ports unverified)</div>')
            else:
                stat = f'<div class="flow-stat">{get_through:,} of {total:,} attack steps get through</div>'
        else:
            stat = f'<div class="flow-stat muted">0 of {total:,} attack steps get through</div>'
        frows.append(
            f'<div class="{cls}"{attrs}>'
            f'<div class="flow-head">'
            f'<span class="flow-pair"><code>{esc(sz)}</code> <span class="arrow">→</span> <code>{esc(dz)}</code></span>'
            f'{state}{dtbtn}</div>{bar}{stat}<div class="flow-chips">{chips}</div>'
            f'{flow_detail_html((sz, dz))}</div>')
    zone_matrix = ("".join(frows) or '<p class="empty-note">No zone traffic.</p>')



    def band_of(prio):
        p = prio or 0
        if p >= 8: return ("crit", "Critical (≥8)")
        if p >= 6: return ("high", "High (6–8)")
        if p >= 4: return ("med", "Medium (4–6)")
        return ("low", "Low (<4)")

    # ---------- path detail rows (click-to-expand) ----------
    def detail_html(vid):
        hs = hops_by_vec.get(vid, [])
        if not hs:
            return ""
        rows = []
        for h in hs:
            if h["verdict"] == "NO_NETWORK":
                continue
            tname = (h["technique"] or "").rsplit("-", 1)[0]
            rule = h.get("rule_name") or "default-deny"
            pids = tech_plugins.get(vid, {}).get(h["technique"]) or []
            ptxt = fix = ""
            patch_items = []
            for pid in pids[:4]:
                e = enrichment.get(str(pid)) or {}
                nm = e.get("plugin_name") or f"plugin {pid}"
                sol = (e.get("solution") or "")[:150]
                vpr = e.get("vpr_score")
                patch_items.append(f'<li><strong>{esc(nm)}</strong> (plugin {esc(pid)}'
                                   + (f', VPR {esc(vpr)}' if vpr else '')
                                   + ')' + (f'<br><span class="sol">Fix: {esc(sol)}</span>' if sol else "") + "</li>")
            patch_html = (f'<li><strong>Patch:</strong><ul>{"".join(patch_items)}</ul>'
                          + ('<span class="more">…and more plugins</span>' if len(pids) > 4 else "")
                          + "</li>") if patch_items else ""
            if h["verdict"] == "ALLOWED":
                edr_line = (f'no EDR on <code>{esc(h["dst"])}</code> — deploy or verify agent '
                            "coverage to contain exploitation" if not h.get("edr_dst")
                            else f'{esc(h.get("edr_dst"))} present on target (containment likely)')
                fix = (f'<div class="pfix"><span class="pfix-h">How to stop this hop</span>'
                       f'<ul>'
                       f'<li><strong>Firewall:</strong> restrict <code>{esc(rule)}</code> — deny '
                       f'{esc(tname)} from <code>{esc(h["src"])}</code> ({esc(h.get("src_zone") or "?")}) '
                       f'to <code>{esc(h["dst"])}</code> ({esc(h.get("dst_zone") or "?")}); '
                       f"blocking this hop alone breaks the path</li>"
                       f'<li><strong>Containment:</strong> {edr_line}</li>'
                       f'{patch_html}'
                       f'</ul></div>')
            elif h["verdict"] == "UNVERIFIED":
                edr_line = (f'no EDR on <code>{esc(h["dst"])}</code>' if not h.get("edr_dst")
                            else f'{esc(h.get("edr_dst"))} present on target')
                fix = (f'<div class="pfix"><span class="pfix-h">How to stop this hop (verify first)</span>'
                       f'<ul>'
                       f'<li><strong>Firewall:</strong> the exploit port is unknown — check whether it falls in '
                       f'<code>{esc(rule)}</code>’s service set; if it does, restrict that policy '
                       f"to the intended services/hosts</li>"
                       f'<li><strong>Containment:</strong> {edr_line}</li>'
                       f'{patch_html}'
                       f'</ul></div>')
            if fix:
                ptxt = fix
            elif patch_items:
                ptxt = (f'<div class="pfix"><span class="pfix-h">Patching that stops this hop</span>'
                        f'<ul>{"".join(patch_items)}</ul></div>')
            pev = ""
            if h.get("observed_ports"):
                pev = (f'<span class="chip info">port {", ".join(str(x) for x in h["observed_ports"])} '
                       f'observed</span>')
            rows.append(
                f'<tr><td><code>{esc(h["src"])}</code></td><td><code>{esc(h["dst"])}</code></td>'
                f"<td>{esc(tname)}</td><td>{hopchip(h['verdict'])}{pev}</td>"
                f"<td>{esc(rule)}</td>"
                f'<td>{esc((h.get("edr_src") or "none") + " → " + (h.get("edr_dst") or "none"))}</td></tr>')
            if ptxt:
                rows.append(f'<tr class="pfixrow"><td colspan="6">{ptxt}</td></tr>')
        tbl = ('<div class="scrollx"><table class="table hops"><thead><tr>'
               "<th>From</th><th>To</th><th>Technique</th><th>Firewall verdict</th>"
               "<th>Deciding rule</th><th>EDR (src → dst)</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>")
        return f'<div class="pdetails" hidden>{tbl}</div>'

    # group same-shaped paths so near-identical rows collapse into one entry
    def group_paths(paths_list):
        groups = collections.defaultdict(list)
        for p in paths_list:
            name = (p.get("name") or "").casefold()
            if not name:
                hs = hops_by_vec.get(p["vector_id"], [])
                name = str(next((h["src"] for h in hs
                                 if h["verdict"] not in ("NO_NETWORK", "NO_ZONES")), p["vector_id"])).casefold()
            fams = tuple(sorted({(t or "").rsplit("-", 1)[0].casefold()
                                 for t in (p.get("techniques") or [])}))
            groups[(name, fams)].append(p)
        out = []
        for key, members in groups.items():
            rep = sorted(members, key=lambda x: -(x.get("priority") or 0))[0]
            out.append((rep, len(members), members))
        out.sort(key=lambda rc: (0 if path_kev(rc[0]["vector_id"]) else 1,
                                 -(rc[0].get("priority") or 0)))
        return out

    def path_kev(vid):
        """KEV evidence per path: (a) plugin xref CISA-KNOWN-EXPLOITED (kev_date
        in the enrichment — strongest, covers KB bundles), and (b) plugin CVEs
        present in the CISA KEV catalog."""
        if not kev_set:
            return []
        pids = set()
        for plist in (tech_plugins.get(vid) or {}).values():
            pids.update(plist)
        hits, seen = [], set()
        for pid in pids:
            e = enrichment.get(str(pid)) or {}
            kd = e.get("kev_date")
            if kd and "xref" not in seen:
                seen.add("xref")
                hits.append({"cve": f"plugin {pid} xref", "date": kd, "plugin": pid})
            for cve in e.get("cves") or []:
                if cve in kev_set and cve not in seen:
                    seen.add(cve)
                    hits.append({"cve": cve, "date": kev_set[cve], "plugin": pid})
        return hits

    def kev_chip(vid):
        hits = path_kev(vid)
        if not hits:
            return ""
        return (f'<span class="chip bad" title="actively exploited (CISA KEV)">'
                f'KEV: {esc(hits[0]["cve"])}'
                + (f' +{len(hits)-1}' if len(hits) > 1 else "") + "</span>")

    def target_edr(vid):
        hs = hops_by_vec.get(vid, [])
        for h in reversed(hs):
            if h.get("edr_dst") is not None:
                return h["edr_dst"]
            if h["verdict"] in ("ALLOWED", "UNVERIFIED", "DENIED", "IMPLICIT"):
                return None
        return None

    def contain_chip(vid):
        hs = hops_by_vec.get(vid, [])
        chips = []
        e = target_edr(vid)
        if e:
            chips.append(f'<span class="chip good" title="EDR present on the path target">EDR: {esc(e)} on target</span>')
        for h in hs:
            if h["verdict"] in ("ALLOWED", "UNVERIFIED") and not h.get("edr_dst"):
                chips.append(f'<span class="chip bad" title="a live hop lands on an endpoint with no EDR">'
                             f'unmanaged hop: {esc(h["dst"])}</span>')
                break
        if not chips and any(h["verdict"] in ("ALLOWED", "UNVERIFIED") for h in hs):
            chips.append('<span class="chip bad" title="no EDR detected on the path target">no EDR on target</span>')
        return " ".join(chips)

    def rule_chips(vid):
        hs = hops_by_vec.get(vid, [])
        bits = []
        for h in hs:
            if h["verdict"] == "ALLOWED" and h.get("rule_name"):
                pev = (f' (port {", ".join(str(x) for x in h["observed_ports"])} observed)'
                       if h.get("observed_ports") else "")
                bits.append(f'<span class="chip bad" title="allowed by firewall policy">'
                            f'allowed by {esc(h["rule_name"])}{pev}</span>')
                break
        for h in hs:
            if h["verdict"] in ("DENIED",) and h.get("rule_name"):
                bits.append(f'<span class="chip good" title="cut by explicit deny rule">'
                            f'denied by {esc(h["rule_name"])}</span>')
                break
            if h["verdict"] == "UNVERIFIED" and h.get("would_allow"):
                bits.append(f'<span class="chip info" title="may pass this policy (port unverified)">'
                            f'may pass {esc(h["would_allow"][0])}</span>')
                break
        return " ".join(bits)

    def path_row(p, tone, count=1, band=None, members=None):
        techs = " ".join(f'<span class="tech">{esc(t.rsplit("-",1)[0])}</span>'
                         for t in (p.get("techniques") or [])[:6])
        hv = " ".join(hopchip(v) for v in p["hop_verdicts"])
        badge = (f'<button class="shapechip" type="button" aria-expanded="false">'
                 f'{count:,} paths with this shape \u25b4</button>'
                 if count > 1 and members else "")
        battr = f' data-band="{esc(band)}"' if band else ""
        shape_detail = ""
        if members:
            rows = []
            for mp in sorted(members, key=lambda x: -(x.get("priority") or 0))[:20]:
                rows.append(
                    f'<tr><td><span class="prio">{mp.get("priority") or "\u2014"}</span></td>'
                    f'<td>{esc(mp.get("name") or mp["vector_id"])}</td>'
                    f'<td>{esc((mp.get("summary") or "")[:120])}</td>'
                    f'<td>\u2192 {esc(mp["paths_to_target"])}</td></tr>')
            more = (f'<p class="note">Showing 20 of {len(members):,} paths in this shape.</p>'
                    if len(members) > 20 else "")
            shape_detail = (f'<div class="pdetails shapedetail" hidden>'
                            f'{more}'
                            f'<div class="scrollx"><table class="table"><thead><tr>'
                            f"<th>Priority</th><th>Attack path</th><th>Summary</th><th>Target</th>"
                            f"</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></div>")
        return (
            f'<div class="prow {tone} clickable" role="button" tabindex="0"{battr}>'
            f'<div class="prow-head"><span class="prio">{p.get("priority") or "—"}</span>'
            f'<span class="pname">{esc(p.get("name") or p["vector_id"])}</span>'
            f'<span class="ptarget">→ {esc(p["paths_to_target"])}</span></div>'
            f'<div class="prow-sub">{esc((p.get("summary") or "")[:160])}</div>'
            f'<div class="prow-chips">{hv}{kev_chip(p["vector_id"])}{rule_chips(p["vector_id"])}{contain_chip(p["vector_id"])}{badge}'
            f'<span class="techwrap">{techs}</span></div>'
            + f"{detail_html(p['vector_id'])}"
            f"{shape_detail}"
            f"</div>")

    live_groups = group_paths(live)
    live_rows = [path_row(p, "bad", c, band=band_of(p.get("priority"))[0])
                 for p, c, members in live_groups[:40]]
    live_html = ("".join(live_rows)
                 or '<p class="empty-note">No confirmed-live paths in this rulebase — every attack path with live hops is listed under "Possible exposure" below, or is cut by policy.</p>')
    live_n_shown = sum(c for _, c, m in live_groups[:40])
    # priority-band breakdown across ALL live paths (not just displayed shapes)
    band_counts = collections.Counter()
    for p in live:
        band_counts[band_of(p.get("priority"))] += 1
    live_bands = ""
    if live:
        chips = []
        for (bkey, blabel), n in sorted(band_counts.items(),
                                        key=lambda kv: ["crit", "high", "med", "low"].index(kv[0][0])):
            chips.append(f'<button class="bandchip" type="button" data-band="{esc(bkey)}">'
                         f'{esc(blabel)} · {n:,}</button>')
        live_bands = ('<div class="bandbar"><span class="pfix-h">Live paths by APA priority — '
                      'click to filter</span><br>' + "".join(chips) + "</div>")
    kev_live = sum(1 for p in live if path_kev(p["vector_id"]))
    kev_note = (f' <strong>{kev_live:,} of {len(live):,} live paths carry actively-exploited '
                f'(CISA KEV) vulnerabilities</strong> — treat as urgent.' if kev_live else "")
    live_more = (f'<p class="note">Showing {live_n_shown:,} of {len(live):,} live paths in {len(live_groups[:40])} shapes — '
                 "click a path to expand its hops, the rule that allows it, per-hop remediation options "
                 "(firewall change, containment, patch), and the patches that stop it. The priority chips above filter "
                 f"the shapes shown. KEV-flagged paths are listed first.{kev_note}</p>")

    # ---------- blocked group by rule ----------
    cut_by = collections.Counter()
    for p in blocked:
        for r in p["blocked_by"]:
            cut_by[r] += 1
    cut_rows = "".join(
        f'<tr><td>{esc(r)}</td><td class="num">{c:,}</td></tr>' for r, c in cut_by.most_common(12))
    blocked_sample = []
    for p, c, members in group_paths(blocked)[:10]:
        hv = " ".join(hopchip(v) for v in p["hop_verdicts"])
        badge = (f'<span class="chip">{c:,} paths with this shape</span>' if c > 1 else "")
        blocked_sample.append(
            f'<div class="prow good clickable" role="button" tabindex="0"><div class="prow-head">'
            f'<span class="prio">{p.get("priority") or "—"}</span>'
            f'<span class="pname">{esc(p.get("name") or p["vector_id"])}</span>'
            f'<span class="ptarget">→ {esc(p["paths_to_target"])}</span></div>'
            f'<div class="prow-chips">{hv}{rule_chips(p["vector_id"])}{badge} '
            f'<span class="cutby">cut by: {esc(", ".join(p["blocked_by"][:3]))}</span></div>'
            f"{detail_html(p['vector_id'])}</div>")

    # ---------- possible exposure (unverified ports) ----------
    possible = sorted([p for p in pvs if p["verdict"] == "PARTIALLY_VERIFIED"],
                      key=lambda x: -(x.get("priority") or 0))
    poss_groups = group_paths(possible)
    poss_rows = [path_row(p, "warn", c, members=members) for p, c, members in poss_groups[:25]]
    poss_html = ("".join(poss_rows)
                 or '<p class="empty-note">No possible-exposure paths.</p>')
    poss_shown = sum(c for _, c, m in poss_groups[:25])
    uncontained = sum(1 for p in possible if target_edr(p["vector_id"]) is None)
    sv = corr.get("services_meta") or {"source": "none"}
    tc, tt = sv.get("targets_covered", 0), sv.get("targets_total", 0)
    cover_line = ""
    if tt and sv.get("source") != "none":
        if tc:
            cover_line = (f'<strong>Scan coverage of attack-path targets: {tc:,} of {tt:,}</strong> — the remaining '
                          f"{tt - tc:,} have no scan evidence, so their exploit ports cannot be verified. "
                          "Recommended action: run a credentialed scan of those subnets.")
        else:
            cover_line = ("<strong>No scan evidence available for any attack-path target</strong> — their exploit "
                          "ports cannot be verified against policy. Recommended action: run a credentialed scan "
                          "of the subnets holding these targets.")
    kev_poss = sum(1 for p in possible if path_kev(p["vector_id"]))
    kev_poss_note = (f'<strong>{kev_poss:,} of {len(possible):,} carry actively-exploited (CISA KEV) '
                     f"vulnerabilities</strong>. " if kev_poss else "")
    if sv.get("source") != "none":
        poss_more = (f'<p class="note">Showing {poss_shown:,} of {len(possible):,} paths in {min(len(poss_groups),25)} shapes. '
                     f"Observed services ({esc(sv.get('source'))}: {sv.get('hosts', 0):,} hosts, "
                     f"{sv.get('services', 0):,} service records) resolve exploit ports where the target's scans "
                     f"show them. {kev_poss_note}{cover_line} "
                     f'<strong>{uncontained:,} of {len(possible):,} land on targets with no EDR</strong> — nothing would '
                     "contain them at the endpoint either.</p>")
    else:
        poss_more = (f'<p class="note">Showing {poss_shown:,} of {len(possible):,} paths in {min(len(poss_groups),25)} shapes. '
                     f"{kev_poss_note}"
                     f"{cover_line} Verify the port, then patch or tighten that rule. Click a path for hop detail and patch options. "
                     f'<strong>{uncontained:,} of {len(possible):,} land on targets with no EDR</strong> — nothing would '
                     "contain them at the endpoint either.</p>")

    # ---------- identity plane ----------
    ID_ADVICE = {
        "Abuse Elevation Control Mechanism": "Privilege-tiering: reduce standing privileged-group membership; enforce tiered admin model",
        "Domain Groups": "Audit privileged group membership; remove stale accounts from Domain Admins and peers",
        "LSASS Memory": "Enable Credential Guard / LSA protection; patch hosts enabling credential-theft techniques",
        "Network Sniffing": "Disable legacy auth protocols; segment VLANs; switch hardening (no hub access, DHCP snooping)",
        "Password Spraying": "Enforce MFA; modern password policy and lockout thresholds; monitor for spraying patterns",
        "Local Groups": "Review local-admin membership; deploy LAPS for local admin rotation",
        "Windows Credential Manager": "Restrict delegated credentials; enable Credential Guard; deny interactive logon for service accounts",
        "Domain Accounts": "Protect Kerberos: strong account policy; monitor anomalous TGS requests",
    }
    ifam = ""
    for f, c in sorted(idstats["families"].items(), key=lambda kv: -kv[1])[:8]:
        advice = next((v for k, v in ID_ADVICE.items() if f.startswith(k)),
                      "Standard AD hardening: least privilege, credential hygiene, tiering")
        ifam += (f'<div class="iflow"><div class="iflow-head"><span class="ifname">{esc(f)}</span>'
                 f'<span class="chip">{c:,} paths</span></div>'
                 f'<div class="ifadvice">{esc(advice)}</div></div>')
    itgt = " ".join(f'<span class="chip bad">{esc(t)} · {c:,}</span>'
                    for t, c in sorted(idstats["targets"].items(), key=lambda kv: -kv[1])[:8])
    identity_html = (
        f'<div class="sub"><strong>{idstats["count"]:,} attack paths ({idstats["count"]/total_paths*100:.0f}% of the estate) '
        f'never touch a routed network hop</strong> — they run entirely through identity (accounts, groups, domains). '
        f'A firewall rule cannot stop them; only identity hygiene can.</div>'
        f'<div class="iflows">{ifam}</div>'
        f'<p class="note">Most-attacked identity targets: {itgt}</p>'
        f'<p class="note">Guidance above is standard AD hardening, not tenant-specific findings — the APA mitigations '
        f'field in this dataset only carries a generic "epp" tag.</p>')

    # ---------- rule impact ----------
    rrows = []
    for r, c in rule_rows:
        rrows.append(
            f'<tr><td>{esc(r)}</td>'
            f'<td class="num">{chip("ALLOWED", c["ALLOWED"])}</td>'
            f'<td class="num">{chip("UNVERIFIED", c["UNVERIFIED"])}</td>'
            f'<td class="num">{chip("IMPLICIT", c["IMPLICIT"])}</td>'
            f'<td class="num">{chip("DENIED", c["DENIED"])}</td>'
            f"</tr>")
    rule_table = ('<div class="scrollx"><table class="table"><thead><tr>'
                  "<th>Policy (first match wins)</th><th>Hops allowed</th>"
                  "<th>Hops that may pass (port unverified)</th>"
                  "<th>Hops cut (default deny)</th><th>Hops cut (explicit deny)</th>"
                  "</tr></thead><tbody>" + "".join(rrows) + "</tbody></table></div>")

    # ---------- remediation ----------
    RISKY_SERVICES = {"SMB", "RDP", "WINRM", "MSRPC", "ALL"}
    # hops grouped by the policy that permits (or may permit) them, with zone pairs
    rule_live = collections.defaultdict(lambda: {"hops": 0, "unverified": 0,
                                                 "pairs": collections.Counter()})
    for h in hops:
        if h["verdict"] == "ALLOWED" and h.get("rule_name"):
            e = rule_live[h["rule_name"]]
            e["hops"] += 1
            e["pairs"][(h.get("src_zone"), h.get("dst_zone"))] += 1
        elif h["verdict"] == "UNVERIFIED":
            for rid in (h.get("would_allow") or []):
                e = rule_live[rid]
                e["unverified"] += 1
                e["pairs"][(h.get("src_zone"), h.get("dst_zone"))] += 1
    pol_by_name = {p["name"]: p for p in rules.get("policies", [])}
    rem_rows = []
    for rname, e in sorted(rule_live.items(),
                           key=lambda kv: -(kv[1]["hops"] + kv[1]["unverified"])):
        pol = pol_by_name.get(rname, {})
        svcs = pol.get("service") or []
        if e["hops"] > 0:
            if any(s.upper() in RISKY_SERVICES for s in svcs):
                rec = "Restrict service set — risky protocol carried by a broad allow"
            else:
                rec = "Tighten srcaddr/dstaddr to named hosts; confirm this allow is required"
        else:
            rec = ("Verify the exploit's port: if it falls in this policy's service set "
                   f"({esc(', '.join(svcs) or 'ALL')}), traffic passes; tighten or split the policy")
        pairs = "<br>".join(f"<code>{esc(a)} → {esc(b)}</code>"
                            for (a, b), c in e["pairs"].most_common(3))
        rem_rows.append(
            f"<tr><td><strong>{esc(rname)}</strong></td>"
            f'<td class="num">{e["hops"]:,}</td>'
            f'<td class="num">{e["unverified"]:,}</td>'
            f"<td>{pairs}</td><td>{rec}</td></tr>")
    remediation = ('<div class="scrollx"><table class="table"><thead><tr>'
                   "<th>Policy permitting (or possibly permitting) traffic</th><th>Live hops</th>"
                   "<th>Possible hops (port unverified)</th><th>Zone pairs</th><th>Recommended action</th>"
                   "</tr></thead><tbody>" + "".join(rem_rows) + "</tbody></table></div>")

    top_t = " ".join(f'<span class="chip info">{esc(t)} · {c}</span>'
                     for t, c in live_tech.most_common(10))
    top_tgt = " ".join(f'<span class="chip bad">{esc(t)} · {c}</span>' for t, c in live_targets.most_common(8))

    out_path = a.out or os.path.join(OUT, f"firewall-paths-dashboard-{a.instance}.html")

    # per-flow path export data: every path (all verdicts), one row per hop —
    # embedded so each zone-pair panel can offer its own CSV download
    flow_paths = {}
    for (sz, dz), per_vec in flow_detail.items():
        rows = []
        for vid, hs in per_vec.items():
            prio, name, _ = prio_by_vec_f.get(vid, (None, vid, ""))
            for h in hs:
                rows.append({
                    "priority": prio,
                    "attack_path": name or vid,
                    "technique": (h["technique"] or "").rsplit("-", 1)[0],
                    "from": h["src"], "to": h["dst"],
                    "verdict": h["verdict"],
                    "rule_reached": h.get("rule_name")
                                    or ", ".join(h.get("would_allow") or [])
                                    or "default-deny",
                    "edr_on_target": h.get("edr_dst") or "none"})
        flow_paths[f"{sz}|{dz}"] = rows
    flow_paths_json = json.dumps(flow_paths).replace("</", "<\\/")

    tiles_html = (
        tile(total_paths, "attack paths (estate)") +
        tile(n_net, "paths with network hops", goto="zones") +
        tile(pvc.get("BLOCKED", 0), "cut by policy / default-deny", "good", goto="blocked") +
        tile(pvc.get("PARTIALLY_VERIFIED", 0), "possible exposure — port unverified", "warn", goto="possible") +
        tile(pvc.get("LIVE", 0), "live — confirmed via named allows", "bad", goto="live-paths") +
        tile(sum(corr["hop_verdict_counts"].values()), "network hops evaluated", goto="zones"))
    wi = corr.get("whatif") or {"scenarios": []}
    wi_cards = ""
    for sc in wi.get("scenarios", []):
        lv = f"{sc['before']['LIVE']:,} → {sc['after']['LIVE']:,}"
        pv = f"{sc['before']['PARTIALLY_VERIFIED']:,} → {sc['after']['PARTIALLY_VERIFIED']:,}"
        cut_examples = " · ".join(
            f"{esc((c.get('name') or 'path')[:50])} (prio {c.get('priority')})"
            for c in sc.get("cut_live_paths", [])[:2])
        wi_cards += (
            f'<div class="wicard">'
            f'<div class="wi-head"><span class="winame">{esc(sc["name"])}</span>'
            f'<span class="chip">{esc(sc["type"])}</span></div>'
            f'<div class="wi-change">{esc(sc["change"])}</div>'
            f'<div class="wi-stats">'
            f'<div class="wistat"><span class="wn">{lv}</span><span class="wl">live paths</span></div>'
            f'<div class="wistat"><span class="wn">{pv}</span><span class="wl">possible exposure</span></div>'
            f'<div class="wistat"><span class="wn">{sc["blocked_delta"]:+,}</span><span class="wl">paths newly cut</span></div>'
            f'</div>'
            + (f'<div class="wi-cut">Cut: {cut_examples}</div>' if cut_examples else "")
            + "</div>")
    if wi.get("scenarios"):
        wi_html = ('<p class="note">Each card re-runs the full correlation with one candidate policy change. '
                   "Deltas are computed, not estimated: the hop engine is replayed with the candidate rule "
                   "inserted before the policy it restricts.</p>" + wi_cards)
    else:
        wi_html = '<p class="empty-note">No what-if scenarios (no policies carry live or possible traffic).</p>'

    edr_meta = corr.get("edr_meta") or {"source": "simulated", "vendors": {}}
    if edr_meta["vendors"]:
        edr_stmt = ("EDR source: " + esc(edr_meta["source"]) + " — " +
                    ", ".join(f"{esc(v)} ({n} assets)" for v, n in
                              sorted(edr_meta["vendors"].items(), key=lambda kv: -kv[1])))
    else:
        edr_stmt = ("EDR source: simulated (SentinelOne zone coverage: core 100%, servers 90%, "
                    "users 50%) — production runs supply --edr-map built from 3rd-party "
                    "connector sources")
    # ---------- ticket export (Layer 1) ----------
    def jira_priority(prio, kev):
        if kev or (prio or 0) >= 8:
            return "Highest"
        if (prio or 0) >= 6:
            return "High"
        if (prio or 0) >= 4:
            return "Medium"
        return "Low"

    def hops_markdown(vid):
        hs = [h for h in hops_by_vec.get(vid, []) if h["verdict"] != "NO_NETWORK"]
        rows = []
        for h in hs:
            ports = ", ".join(str(x) for x in (h.get("observed_ports") or h.get("ports") or [])) or "?"
            rows.append(f"|{esc(h['src'])}|{esc(h['dst'])}|{esc((h['technique'] or '').rsplit('-',1)[0])}"
                        f"|{ports}|{esc(h['verdict'])}|{esc(h.get('rule_name') or 'default-deny')}|")
        return "||From||To||Technique||Port||Verdict||Rule||\n" + "\n".join(rows)

    def plugins_markdown(vid):
        pids = set()
        for plist in (tech_plugins.get(vid) or {}).values():
            pids.update(plist)
        items = []
        for pid in sorted(pids)[:5]:
            e = enrichment.get(str(pid)) or {}
            nm = e.get("plugin_name") or f"plugin {pid}"
            sol = (e.get("solution") or "").strip()
            items.append(f"* [{esc(nm)}] (plugin {pid}"
                         + (f", VPR {e.get('vpr_score')}" if e.get("vpr_score") else "") + ")"
                         + (f" — Fix: {sol}" if sol else ""))
        return "\n".join(items) or "n/a"

    tickets = []
    for p, c, members in live_groups:
        vid = p["vector_id"]
        kev_hits = path_kev(vid)
        prio = p.get("priority")
        pr = jira_priority(prio, bool(kev_hits))
        title = f"[Exposure] Attack path: {p.get('name') or vid} → {p['paths_to_target']} (priority {prio})"
        kev_line = ("* *Actively exploited (CISA KEV):* " + "; ".join(
            f'{esc(h["cve"])} (added {esc(h.get("date") or "?")})' for h in kev_hits) + "\n") if kev_hits else ""
        edr_t = target_edr(vid)
        edr_line = f"* *EDR on target:* {esc(edr_t)}\n" if edr_t else "* *EDR on target:* none — containment gap\n"
        desc = (f"h2. Summary\n"
                f"Attack path reaches {{color:red}}{esc(p['paths_to_target'])}{{color}} with APA priority "
                f"{prio}. Firewall verdict: LIVE — every network hop passes a named allow rule.\n\n"
                f"h2. Evidence ({esc(instance_lbl)} — generated {esc(generated)})\n"
                f"{hops_markdown(vid)}\n\n"
                f"h2. Exploitation\n{kev_line}{edr_line}"
                f"h2. Recommended actions\n"
                f"* *Firewall:* restrict the allow rule(s) carrying this path (see Remediation what-if for computed deltas)\n"
                f"* *Patch:*\n{plugins_markdown(vid)}\n\n"
                f"h2. Labels\nfirewall-path-validation, exposure, live, kev" if kev_hits else "")
        tickets.append({"id": f"AP:{vid}", "type": "attack_path", "system": "jira",
                        "title": title, "priority": pr, "labels": "firewall-path-validation,exposure,live,kev",
                        "markdown": desc})

    for sc in wi.get("scenarios", []):
        desc = (f"h2. Summary\n"
                f"Pre-validated firewall change: {esc(sc['change'])}\n\n"
                f"h2. Computed impact (full correlation replay, not an estimate)\n"
                f"* Live attack paths: {{color:red}}{sc['before']['LIVE']:,} → {sc['after']['LIVE']:,}{{color}}\n"
                f"* Possible exposure: {sc['before']['PARTIALLY_VERIFIED']:,} → {sc['after']['PARTIALLY_VERIFIED']:,}\n"
                f"* Paths newly cut: {sc['blocked_delta']:,}\n\n"
                f"h2. Paths cut (top examples)\n"
                + "\n".join(f"* {esc((c.get('name') or 'path')[:70])} (priority {c.get('priority')}) → {esc(c.get('target'))}"
                             for c in sc.get("cut_live_paths", [])[:3]) + "\n\n"
                f"h2. Labels\nfirewall-path-validation, policy-change, {sc['type']}")
        tickets.append({"id": f"PC:{sc['rule']}", "type": "policy_change", "system": "jira",
                        "title": f"[Firewall change] {sc['name']} — cuts {sc['blocked_delta']:,} paths (computed)",
                        "priority": "High" if sc["blocked_delta"] > 0 else "Medium",
                        "labels": f"firewall-path-validation,policy-change,{sc['type']}",
                        "markdown": desc})

    import csv as _csv, io as _io
    buf = _io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["ticket_type", "title", "priority", "labels", "description_markdown"])
    for t in tickets:
        w.writerow([t["type"], t["title"], t["priority"], t["labels"], t["markdown"]])
    tickets_csv = buf.getvalue()
    tickets_md = "\n\n---\n\n".join(t["markdown"] for t in tickets)


    blk = pvc.get("BLOCKED", 0)
    live_n = pvc.get("LIVE", 0)
    poss_n = pvc.get("PARTIALLY_VERIFIED", 0)
    blk_pct = blk / max(n_net, 1) * 100


    # ---------- triage queue: top actionable items across all sections ----------
    def route_to(kind):
        return {"firewall": "network team", "patch": "patching team",
                "identity": "identity team", "scan": "scanning team"}.get(kind, "security team")

    triage_items = []

    # 1. firewall changes from what-if (highest computed impact first)
    for sc in sorted(wi.get("scenarios", []), key=lambda x: -x["blocked_delta"]):
        if sc["blocked_delta"] == 0 and sc["before"]["LIVE"] == 0:
            continue
        sev = "red" if sc["before"]["LIVE"] > 0 or sc["blocked_delta"] > 500 else "amber"
        impact = (f'{sc["before"]["LIVE"]:,} → {sc["after"]["LIVE"]:,} live'
                  + (f', {sc["blocked_delta"]:,} newly cut' if sc["blocked_delta"] else ""))
        triage_items.append({
            "sev": sev, "action": sc["change"], "route": route_to("firewall"),
            "impact": impact, "goto": "whatif", "kind": "firewall"})

    # 2. live-path patches (KEV first, then by path count)
    for p, c, members in live_groups[:10]:
        kev = path_kev(p["vector_id"])
        if not kev:
            continue
        pids = set()
        for plist in (tech_plugins.get(p["vector_id"]) or {}).values():
            pids.update(plist)
        kb_plugins = [enrichment.get(str(pid)) or {} for pid in pids
                      if enrichment.get(str(pid), {}).get("kev_date")]
        patch_names = sorted({e.get("plugin_name", f"plugin {pid}")
                              for e in kb_plugins if e.get("plugin_name")})[:3]
        if not patch_names:
            # fall back to plugins with CVEs in the KEV set
            patch_names = sorted({enrichment.get(str(pid), {}).get("plugin_name", f"plugin {pid}")
                                  for pid in pids
                                  if any(c in kev_set for c in enrichment.get(str(pid), {}).get("cves", []))})[:3]
        target = p["paths_to_target"]
        sev = "red"
        impact = f'{c:,} live path(s) → {esc(target)}'
        triage_items.append({
            "sev": sev,
            "action": f'Patch {esc(", ".join(patch_names))} on {esc(target)} — actively exploited (CISA KEV)',
            "route": route_to("patch"), "impact": impact, "goto": "live-paths", "kind": "patch"})

    # 3. scan coverage gap
    sv = corr.get("services_meta") or {}
    if sv.get("targets_covered", 0) < sv.get("targets_total", 0):
        triage_items.append({
            "sev": "amber",
            "action": f'Run a credentialed scan of the {sv.get("targets_total", 0) - sv.get("targets_covered", 0)} '
                      f'attack-path targets with no scan evidence — this unlocks port-level verdicts for '
                      f'{poss_n:,} possible-exposure paths',
            "route": route_to("scan"), "impact": f'{sv.get("targets_covered", 0)}/{sv.get("targets_total", 0)} targets scanned',
            "goto": "possible", "kind": "scan"})

    # 4. identity top actions (top 3 families with remediation advice)
    for fam, cnt in sorted(idstats["families"].items(), key=lambda kv: -kv[1])[:3]:
        advice = next((v for k, v in ID_ADVICE.items() if fam.startswith(k)),
                      "Standard AD hardening: least privilege, credential hygiene, tiering")
        triage_items.append({
            "sev": "yellow", "action": f'{esc(fam)} — {esc(advice)}',
            "route": route_to("identity"), "impact": f'{cnt:,} identity-only paths',
            "goto": "identity", "kind": "identity"})

    # render the triage queue
    triage_rows = []
    for i, t in enumerate(triage_items[:10]):
        tone = {"red": "bad", "amber": "warn", "yellow": ""}.get(t["sev"], "")
        icon = {"red": "🔴", "amber": "🟡", "yellow": "🟠"}.get(t["sev"], "•")
        triage_rows.append(
            f'<div class="triage-item" role="button" tabindex="0" data-goto="{esc(t["goto"])}">'
            f'<span class="triage-icon">{icon}</span>'
            f'<span class="triage-action">{t["action"]}</span>'
            f'<span class="triage-meta"><span class="chip">{esc(t["impact"])}</span>'
            f'<span class="chip">→ {esc(t["route"])}</span></span></div>')
    triage_html = ("".join(triage_rows)
                   or '<p class="empty-note">No actionable items — the firewall covers the estate.</p>')

    # ---------- critical callouts ----------
    kev_live_n = sum(1 for p in live if path_kev(p["vector_id"]))
    kev_poss_n = sum(1 for p in possible if path_kev(p["vector_id"]))
    callouts = ""
    if kev_live_n:
        callouts += (f'<div class="callout bad"><strong>🔴 {kev_live_n:,} of {len(live):,} confirmed-live paths '
                     f'carry actively-exploited (CISA KEV) vulnerabilities.</strong> '
                     f'{kev_poss_n:,} of {len(possible):,} possible-exposure paths are also KEV-flagged. '
                     f'These are being exploited in the wild right now.</div>')
    if idstats["count"]:
        callouts += (f'<div class="callout warn"><strong>🟡 {idstats["count"]:,} attack paths '
                     f'({idstats["count"]/total_paths*100:.0f}% of the estate) run entirely through identity — '
                     f'a firewall cannot help.</strong> The fix is credential hygiene and privilege tiering, '
                     f'not network segmentation.</div>')
    if sv.get("targets_covered", 0) < sv.get("targets_total", 0) and sv.get("source", "none") != "none":
        gap = sv["targets_total"] - sv["targets_covered"]
        callouts += (f'<div class="callout info"><strong>ℹ️ {gap} attack-path targets have no scan '
                     f'evidence.</strong> Running a credentialed scan would turn '
                     f'{poss_n:,} possible-exposure paths into named verdicts.</div>')

    tokens = {
        "@@INSTANCE@@": esc(a.instance),
        "@@GENERATED@@": esc(generated),
        "@@FWNOTE@@": esc(a.firewall_note),
        "@@TILES@@": tiles_html,
        "@@BLK@@": f"{blk:,}",
        "@@BLKPCT@@": f"{blk_pct:.0f}",
        "@@LIVE@@": f"{live_n:,}",
        "@@POSSIBLE@@": f"{poss_n:,}",
        "@@ZONEMATRIX@@": zone_matrix,
        "@@FLOWPATHS@@": flow_paths_json,
                "@@LOGO@@": logo_html,
        "@@LIVEPATHS@@": live_html,
        "@@LIVEBANDS@@": live_bands,
        "@@CUTROWS@@": cut_rows,
        "@@BLOCKEDSAMPLE@@": "".join(blocked_sample),
        "@@RULETABLE@@": rule_table,
        "@@REMEDIATION@@": remediation,
        "@@TOPT@@": top_t,
        "@@TOPTGT@@": top_tgt,
        "@@NOZONES@@": f"{hvc.get('NO_ZONES', 0)}",
        "@@EDRSOURCE@@": edr_stmt,
        "@@WHATIF@@": wi_html,
        "@@TRIAGE@@": triage_html,
        "@@CALLOUTS@@": callouts,

        "@@TICKETCSVNAME@@": f"remediation_tickets_{a.instance}.csv",
        "@@SERVICESMETA@@": (esc((corr.get("services_meta") or {}).get("source")
                                 + f" — {(corr.get('services_meta') or {}).get('hosts', 0):,} hosts, "
                                   f"{(corr.get('services_meta') or {}).get('services', 0):,} service records"
                                   f"; scan coverage of attack-path targets {tc if (corr.get('services_meta') or {}).get('source', 'none') != 'none' else 0:,}/{tt if (corr.get('services_meta') or {}).get('source', 'none') != 'none' else 0:,}")
                             if (corr.get("services_meta") or {}).get("source", "none") != "none"
                             else "none supplied — unknown-port hops stay UNVERIFIED"),
        "@@IDENTITY@@": identity_html,
        "@@POSSPATHS@@": poss_html,
        "@@POSSMORE@@": poss_more,
        "@@LIVEMORE@@": live_more,
        "@@IDENTTILE@@": tile(idstats["count"], "identity-only paths (no firewall effect)", goto="identity"),
    }
    page = TEMPLATE
    for k, v in tokens.items():
        page = page.replace(k, v)
    with open(out_path, "w") as f:
        f.write(page)
    if tickets:
        base = os.path.splitext(out_path)[0]
        csv_p = base + "_tickets.csv"
        with open(csv_p, "w", newline="", encoding="utf-8") as fh:
            fh.write(tickets_csv)
        md_p = base + "_tickets.md"
        with open(md_p, "w", encoding="utf-8") as fh:
            fh.write(f"# Remediation tickets — {a.instance}\n\n" +
                     "\n\n---\n\n".join(t["markdown"] for t in tickets))
        print(f"wrote {csv_p} ({len(tickets)} tickets)")
        print(f"wrote {md_p}")
    print(f"wrote {out_path} ({os.path.getsize(out_path)/1024:.0f} KB)")

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="claude:viewport-fit-sides" content="cover">
<title>Firewall Path Validation</title>
<style>
:root {
  /* Tenable brand as used by the choke-point dashboard:
     near-black charcoal + white + lime accent, dark-only */
  color-scheme: dark;
  --bg: #17191b; --surface: #202325; --surface2: #1a1c1e; --line: #33373b;
  --fg: #f5f6f7; --muted: #9aa0a6;
  --accent: #d2f34c; --accent-ink: #17191b;
  --good: #d2f34c; --bad: #f0586a; --warn: #ffd166; --info: #5aa6ff;
}
body { background: var(--bg); color: var(--fg);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  padding-left: max(16px, env(safe-area-inset-left, 0px));
  padding-right: max(16px, env(safe-area-inset-right, 0px));
  padding-block: 24px; font-variant-numeric: tabular-nums; }
.wrap { max-width: 1080px; margin: 0 auto; }
.brandbar { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 4px; }
.brandlogo { height: 26px; max-width: 180px; width: auto; }
.brandsep { display: inline-block; width: 1px; height: 22px; background: var(--line); }
.brandfallback { display: inline-flex; align-items: center; gap: 8px; }
.brandword { font: 800 24px/1 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  letter-spacing: -1.3px; color: var(--accent); }
.eyebrow { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .12em; }
h1 { font-size: 26px; margin: 4px 0 2px; text-wrap: balance; }
.sub { color: var(--muted); font-size: 13px; }
h2 { font-size: 17px; margin: 36px 0 6px; }
.note { color: var(--muted); font-size: 12px; margin: 2px 0 12px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin: 20px 0; }
.tile { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 14px; }
.tile-n { font-size: 26px; font-weight: 700; }
.tile.bad .tile-n { color: var(--bad); } .tile.good .tile-n { color: var(--good); }
.tile.warn .tile-n { color: var(--warn); } .tile.accent .tile-n { color: var(--accent); }
.tile-l { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .08em; margin-top: 2px; }
.tile[data-goto] { cursor: pointer; }
.tile[data-goto]:hover { border-color: var(--accent); }
.tile[data-goto]:focus-visible { outline: 2px solid var(--accent); }
.headline { background: var(--surface); border-left: 3px solid var(--accent);
  padding: 14px 16px; border-radius: 0 8px 8px 0; margin: 16px 0; font-size: 15px; }
.chip { display: inline-block; font-size: 11px; padding: 1px 7px; border-radius: 999px;
  border: 1px solid var(--line); color: var(--muted); margin: 1px; }
.chip.good { color: var(--good); border-color: var(--good); }
.chip.bad { color: var(--bad); border-color: var(--bad); }
.chip.warn { color: var(--warn); border-color: var(--warn); }
.chip.info { color: var(--info); border-color: var(--info); }
.scrollx { overflow-x: auto; }
table.table { border-collapse: collapse; width: 100%; font-size: 13px; }
.table th, .table td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); }
.table th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }
td.num, .num { white-space: nowrap; }
code { background: var(--surface2); padding: 1px 5px; border-radius: 4px; font-size: 12px; }
.legend { display: flex; gap: 14px; flex-wrap: wrap; margin: 2px 0 10px; font-size: 12px; color: var(--muted); }
.legend .swatch { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 5px; vertical-align: -1px; }
.flow { background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
  padding: 10px 14px; margin: 8px 0; }
.flow-head { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; min-width: 0; }
.flow-pair { font-weight: 600; }
.flow-pair .arrow { color: var(--muted); }
.flow-state { font-size: 11.5px; padding: 1px 8px; border-radius: 999px; border: 1px solid var(--line); }
.flow-state.good { color: var(--good); border-color: var(--good); }
.flow-state.bad { color: var(--bad); border-color: var(--bad); }
.flow-state.warn { color: var(--warn); border-color: var(--warn); }
.flow-bar { display: flex; height: 12px; border-radius: 6px; overflow: hidden; margin: 7px 0 5px; background: var(--surface2); }
.seg { height: 100%; }
.seg-bad { background: var(--bad); }
.seg-warn { background: var(--warn); }
.seg-good { background: var(--good); }
.seg-info { background: var(--info); }
.flow-chips { font-size: 11px; }
.flow-stat { font-size: 12.5px; font-weight: 600; margin-top: 2px; }
.wicard { background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
  padding: 12px 14px; margin: 10px 0; }
.wi-head { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
.winame { font-weight: 700; }
.wi-change { color: var(--muted); font-size: 12.5px; margin: 4px 0; }
.wi-stats { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 6px; }
.wistat { background: var(--surface2); border-radius: 6px; padding: 6px 12px; min-width: 120px; }
.wistat .wn { display: block; font-weight: 700; font-size: 13.5px; }
.wistat .wl { display: block; color: var(--muted); font-size: 10.5px; text-transform: uppercase;
  letter-spacing: .07em; margin-top: 2px; }
.wi-cut { color: var(--muted); font-size: 12px; margin-top: 6px; }
.shapechip { background: var(--surface2); color: var(--fg); border: 1px solid var(--line);
  border-radius: 6px; padding: 2px 8px; font-size: 11.5px; cursor: pointer; margin-left: 4px; }
.shapechip:hover { border-color: var(--accent); }
.shapedetail { margin-top: 8px; border-top: 1px dashed var(--line); padding-top: 8px; }
.triage-item { background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
  padding: 10px 14px; margin: 6px 0; display: flex; gap: 10px; align-items: flex-start;
  cursor: pointer; flex-wrap: wrap; }
.triage-item:hover { border-color: var(--accent); }
.triage-icon { font-size: 14px; min-width: 20px; }
.triage-action { flex: 1; min-width: 200px; font-size: 13px; }
.triage-meta { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 4px; }
.callout { border-radius: 8px; padding: 12px 16px; margin: 10px 0; font-size: 13.5px; }
.callout.bad { background: var(--surface); border-left: 3px solid var(--bad); }
.callout.warn { background: var(--surface); border-left: 3px solid var(--warn); }
.callout.info { background: var(--surface); border-left: 3px solid var(--info); }
.bandbar { margin: 8px 0 4px; }
.bandchip { background: var(--surface2); color: var(--fg); border: 1px solid var(--line);
  border-radius: 999px; padding: 3px 12px; font-size: 12px; cursor: pointer; margin: 2px; }
.bandchip:hover { border-color: var(--accent); }
.bandchip.on { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }
.flow-stat.muted { color: var(--muted); font-weight: 500; }
.prow { background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
  padding: 10px 14px; margin: 8px 0; border-left-width: 3px; }
.prow.bad { border-left-color: var(--bad); } .prow.good { border-left-color: var(--good); }
.prow.warn { border-left-color: var(--warn); }
.prow-head { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
.prio { font-weight: 700; font-size: 13px; min-width: 30px; }
.pname { font-weight: 600; }
.ptarget { color: var(--muted); font-size: 12px; }
.prow-sub { color: var(--muted); font-size: 12px; margin: 3px 0; }
.prow-chips { margin-top: 4px; }
.prow.clickable { cursor: pointer; }
.prow.clickable .prow-head::after { content: "▾ details"; color: var(--muted);
  font-size: 11px; margin-left: auto; }
.pdetails { margin-top: 8px; border-top: 1px dashed var(--line); padding-top: 8px; }
.pfix { background: var(--surface2); border-radius: 6px; padding: 8px 10px; margin: 4px 0; }
.pfix-h { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }
.pfix ul { margin: 4px 0 0; padding-left: 18px; font-size: 12.5px; }
.pfix .sol { color: var(--muted); }
.pfix .more { color: var(--muted); font-size: 11px; }
.iflow { background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
  padding: 10px 14px; margin: 8px 0; }
.iflow-head { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
.ifname { font-weight: 600; }
.ifadvice { color: var(--muted); font-size: 12.5px; margin-top: 3px; }
.iflows { margin: 10px 0; }
.dlbtn { background: var(--surface2); color: var(--fg); border: 1px solid var(--line);
  border-radius: 6px; padding: 4px 12px; font-size: 12.5px; cursor: pointer; margin-left: 8px; }
.dlbtn:hover { border-color: var(--accent); }
.dlbtn:active { transform: translateY(1px); }
.dtbtn { background: var(--surface2); color: var(--fg); border: 1px solid var(--line);
  border-radius: 999px; padding: 2px 12px; font-size: 11.5px; cursor: pointer; margin-left: auto; }
.dtbtn:hover { border-color: var(--accent); }
.panel-tools { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; margin: 4px 0 8px; }
.panel-tools .note { margin: 0; }
.tech { display: inline-block; font-size: 10.5px; color: var(--muted);
  border: 1px solid var(--line); border-radius: 4px; padding: 0 5px; margin: 1px; }
.cutby { color: var(--warn); font-size: 12px; }
.empty-note { color: var(--muted); font-style: italic; }
footer { color: var(--muted); font-size: 11.5px; border-top: 1px solid var(--line);
  margin-top: 40px; padding-top: 12px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brandbar">@@LOGO@@
      <div class="eyebrow">Tenable One × Firewall Policy — Attack Path Validation</div>
    </div>
    <h1>Which attack paths actually survive your firewall?</h1>
    <p class="sub">Attack paths from Tenable One (APA) evaluated hop-by-hop against the firewall rulebase. @@INSTANCE@@ · @@GENERATED@@</p>
    <p class="sub">Firewall source: @@FWNOTE@@</p>
  </header>

  <div class="tiles">
    @@TILES@@
    @@IDENTTILE@@
  </div>

  <div class="headline">
    <strong>@@BLK@@ attack paths (@@BLKPCT@@% of network-relevant paths) are cut by policy or default-deny.</strong>
    @@POSSIBLE@@ paths may still reach their target through a policy that permits their exploit's port — those need port-level verification.
    @@LIVE@@ paths are confirmed live through named allows.
  </div>

  <h2 id="triage">Triage queue — start here</h2>
  <p class="note">The top actionable items across every section of this dashboard, ranked by severity and computed impact.
     Each item links to its evidence below and shows which team should own it.</p>
  @@TRIAGE@@

  @@CALLOUTS@@

  <h2 id="whatif">Remediation what-if simulator</h2>
  <p class="note">Each card re-runs the full correlation with one candidate policy change — deltas are computed by replaying the hop engine, not estimated. Every item in the triage queue that starts with "restrict" or "remove" is one of these cards.</p>
  @@WHATIF@@

  <h2 id="remediation">Remediation focus</h2>
  @@REMEDIATION@@
  <p class="note">Techniques still reaching live targets: @@TOPT@@</p>
  <p class="note">Live-path targets (most-attacked): @@TOPTGT@@</p>

  <h2 id="live-paths">Confirmed live attack paths</h2>
  <p class="note">Paths whose every network hop passes a named allow rule with a known port. Ranked by APA priority. Click a path for hops, the rule that allows it, and per-hop remediation options (firewall change, containment, patch).</p>
  @@LIVEBANDS@@
  @@LIVEPATHS@@
  @@LIVEMORE@@

  <h2 id="possible">Possible exposure — attacks that reach a policy</h2>
  <p class="note">These paths' exploit hops have an unknown port. Each hop hits an allow rule that <em>may</em> carry it — the verdict depends on whether the exploit's port falls inside that rule's service set.</p>
  @@POSSPATHS@@
  @@POSSMORE@@

  <h2 id="zones">Network corridors — supporting evidence</h2>
  <p class="note">Each row is a <strong>corridor</strong> between two firewall zones — many different attack steps use the same
     corridor, and your firewall does not treat them all the same way. That is why one bar carries several colours:
     it splits every attack step using that corridor by outcome. <strong>Red</strong> = the step succeeds,
     <strong>blue</strong> = the step reaches an allow rule and may succeed (the exploit's port is unknown),
     <strong>amber</strong> = cut by the firewall's default deny, <strong>green</strong> = cut by an explicit deny rule.
     Corridors carrying successful (or possibly successful) steps are listed first.</p>
  <div class="legend">
    <span><span class="swatch" style="background:var(--bad)"></span>allowed — hop succeeds (live exposure)</span>
    <span><span class="swatch" style="background:var(--info)"></span>reaches an allow rule, exploit port unverified</span>
    <span><span class="swatch" style="background:var(--warn)"></span>cut by default deny</span>
    <span><span class="swatch" style="background:var(--good)"></span>cut by an explicit deny rule</span>
  </div>
  @@ZONEMATRIX@@

  <h2 id="blocked">What the firewall already blocks</h2>
  <p class="note">Paths overstated in risk because the rulebase cuts at least one hop. Grouped by cutting control:</p>
  <div class="scrollx"><table class="table"><thead><tr><th>Control</th><th>Paths cut</th></tr></thead><tbody>@@CUTROWS@@</tbody></table></div>
  <h3 class="note">Examples</h3>
  @@BLOCKEDSAMPLE@@

  <h2 id="identity">Identity attack paths — a firewall cannot help here</h2>
  @@IDENTITY@@

  <h2 id="rules">Rule impact</h2>
  @@RULETABLE@@

  <footer>
    <strong>Method.</strong> APA topology via Tenable One top-attack-paths. Hop ports derived from technique families
    (RDP 3389, WinRM 5985/86, SMB 445, MSRPC 135, Kerberos 88/464; exploit ports unknown →
    hop is UNVERIFIED unless an ALL-service rule matches or the target's own scan evidence
    resolves the exploit port — never guessed as live). Observed services: @@SERVICESMETA@@.
    EDR presence is a containment overlay only — it never changes firewall verdicts.
    @@EDRSOURCE@@.
    Firewall semantics: FortiGate first-match-wins, default deny. Identity hops (groups/domains) are out of network scope.
    Zone assignment covered all but @@NOZONES@@ hop endpoints (excluded).
    <br><strong>Limitations.</strong> Firewall data here is simulated for demonstration. Zone assignment is name/label-derived;
    unmapped endpoints are excluded. NAT, IPv6 and routing asymmetry are not modeled. Do not use as a substitute for
    vendor-verified policy review.
  </footer>
</div>
<script>
var FLOW_PATHS = @@FLOWPATHS@@;
(function () {
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  document.querySelectorAll("[data-goto]").forEach(function (t) {
    t.addEventListener("click", function () {
      var el = document.getElementById(t.getAttribute("data-goto"));
      if (el) el.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
    });
    t.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); t.click(); }
    });
  });
  var activeBand = null;
  document.querySelectorAll(".bandchip").forEach(function (b) {
    b.addEventListener("click", function () {
      var band = b.getAttribute("data-band");
      activeBand = (activeBand === band) ? null : band;
      document.querySelectorAll(".bandchip").forEach(function (x) {
        x.classList.toggle("on", x.getAttribute("data-band") === activeBand);
      });
      document.querySelectorAll('.prow[data-band]').forEach(function (r) {
        r.hidden = activeBand !== null && r.getAttribute("data-band") !== activeBand;
      });
    });
  });
  function toggle(el) {
    el.querySelectorAll(":scope > .pdetails:not(.shapedetail)").forEach(function (d) { d.hidden = !d.hidden; });
  }
  document.querySelectorAll(".prow.clickable, .flow.clickable").forEach(function (el) {
    el.addEventListener("click", function () { toggle(el); });
    el.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(el); }
    });
  });
  document.querySelectorAll(".shapechip").forEach(function (b) {
    b.addEventListener("click", function (e) {
      e.stopPropagation();
      var row = b.closest(".prow");
      var d = row.querySelector(".shapedetail");
      if (d) {
        d.hidden = !d.hidden;
        b.setAttribute("aria-expanded", String(!d.hidden));
        b.textContent = d.hidden
          ? b.textContent.replace(" \u25b2", " \u25b4")
          : b.textContent.replace(" \u25b4", " \u25b2");
      }
    });
  });
  document.querySelectorAll(".flow .dtbtn").forEach(function (b) {
    b.addEventListener("click", function (e) {
      e.stopPropagation();
      var f = b.closest(".flow");
      var d = f.querySelector(".pdetails");
      if (d) {
        d.hidden = !d.hidden;
        b.textContent = d.hidden ? "Details ▾" : "Close ▴";
        b.setAttribute("aria-expanded", String(!d.hidden));
      }
    });
  });
  function csvDownload(rows, cols, filename) {
    try {
      var escCell = function (v) { return '"' + String(v === null || v === undefined ? "" : v).replace(/"/g, '""') + '"'; };
      var lines = [cols.join(",")].concat(rows.map(function (r) {
        return cols.map(function (c) { return escCell(r[c]); }).join(",");
      }));
      var blob = new Blob([lines.join("\\n")], { type: "text/csv" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
    } catch (e) { /* downloads can be blocked in embedded viewers */ }
  }
  document.querySelectorAll("[data-flowcsv]").forEach(function (b) {
    b.addEventListener("click", function (e) {
      e.stopPropagation();
      var key = b.getAttribute("data-flowcsv");
      csvDownload(FLOW_PATHS[key] || [],
        ["priority", "attack_path", "technique", "from", "to", "verdict", "rule_reached", "edr_on_target"],
        "attack_paths_" + key.replace("|", "_to_") + ".csv");
    });
  });
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
