---
name: tenable-attack-path-firewall
description: "Validate Tenable One attack paths against an actual firewall rulebase. Pulls firewall policies live from any firewall vendor with a compatible MCP server (Fortinet FortiGate, Palo Alto Networks, Check Point, Cisco and others), or from an offline/exported rulebase file, then evaluates every network-relevant attack-path hop against first-match-wins policy semantics and reports which attack paths the firewall already blocks (overstated risk) vs which survive (true exposure). Produces a self-contained HTML dashboard with a zone traffic matrix, live-path urgency list, rule impact table and remediation focus. Use when a user wants to know if attack paths are blocked by firewall rules, whether network segmentation breaks attack paths, exposure vs firewall policy, attack path validation, which paths survive the firewall, FortiGate/Palo Alto/Check Point/Cisco firewall policy analysis, imported firewall rules file analysis, zone traffic matrix, overstated attack paths. Requires a Tenable One / Exposure Management MCP server."
---

# Firewall-Aware Attack Path Validation

Attack-path analysis tells you what an attacker *could* do. Firewall policy decides what they
*can actually reach*. This skill joins the two: it pulls the firewall rulebase (from a vendor
MCP server — simulated FortiGate included — or an imported normalized rulebase), maps every
Tenable One attack path to hops between firewall zones, evaluates each hop under
first-match-wins / default-deny semantics, and produces a single self-contained HTML
dashboard answering:

- **Which attack paths are already cut by the firewall?** (overstated risk — stop chasing them)
- **Which attack paths survive the rulebase?** (true exposure — patch or tighten policy)
- **Which firewall rules matter most**, and what to change.

**Read `references/firewall-model.md` before correlating** — it defines the normalized rule
model, zone semantics, and verdict meanings. Use `references/technique-ports.md` for the
technique→port mapping the engine applies.

## Phase 0.0 — Configuration manifest (show this first)

Before running anything, present the user with this manifest — what the skill uses,
what it needs from them, and what each item unlocks. Mark each row ✅ available or
⚠️ missing for THIS session. The skill uses **MCP tools wherever a tool exists**;
direct API calls are made only by the pipeline scripts listed, and only when the user
chooses to run them.

| # | Input | How it's used | Required? | Connect via |
|---|---|---|---|---|
| 1 | Tenable One MCP server | attack-path inventory queries, EDR connector sources | **Required** (one instance with APA data) | `claude mcp add` — Tenable One MCP |
| 2 | Attack-path topology fetch | the full path graph (nodes, techniques, priorities) | **Required** | REST script only — **no MCP tool exists**: `fetch_and_correlate.py` (`POST /api/v1/t1/apa/top-attack-paths/search`). Keys are read in-process from the MCP server entry in `~/.claude.json` (nothing printed) or via env `TIO_ACCESS_KEY`/`TIO_SECRET_KEY` |
| 3 | Firewall rulebase | the policy chain every hop is evaluated against | **Required** | Vendor MCP (FortiGate reference impl.) · `--rules` JSON · or demo mode (`--simulate`, opt-in) |
| 4 | EDR connectors | containment overlay (which targets have EDR) | Optional | MCP: `tenable_one_search_assets` with `sources=[vendor]` (in-session) · script fallback `build_edr_map.py` |
| 5 | VM scan data (services) | resolves unknown-port exploit hops to named verdicts | Optional | Script: `fetch_vuln_export_services.py` (**supported `/vulns/export` endpoint** — replaces the deprecated Workbench Export, removed 2027-02-01) · alternative: `fetch_scan_services.py` or `parse_vm_services.py` on any `.nessus` |
| 6 | CISA KEV catalog | flags actively-exploited paths | Optional (auto) | Public HTTPS feed, no keys; cached to `output/kev.json` |

**Key handling, stated plainly to the user:** API scripts never hardcode or print keys.
They read them (a) in-process from the connected MCP server's `X-ApiKeys` entry in
`~/.claude.json`, or (b) from env variables. If a customer prefers env-based keys:
`export TIO_ACCESS_KEY=... TIO_SECRET_KEY=...` before running the scripts. Without
either, the script says exactly which one to set and exits — it never silently proceeds.

Run the manifest check before any fetch: count connected Tenable One MCP servers with
APA data, detect firewall source, probe EDR/VM availability, and report missing
items with the exact command or env var to supply. Do not proceed with degraded
sources until the user has seen the manifest.

### Instances: one MCP connection per run — data is never combined

Each connected Tenable MCP server is a **separate tenant**. A run uses exactly **one**
instance for all its data: attack paths, EDR connectors, and scan data all come from the
same MCP connection. Never combine, join, or mix data across MCP connections — the join
keys (hostnames, asset IDs) are tenant-scoped, and cross-instance joins produce
meaningless results.

At Phase 0.0, list every connected Tenable One MCP server (with its APA-population
status) and **ask the user which one to pull the data from**. If only one is connected,
use it without asking. State clearly that everything in this run comes from that single
instance, and that the optional inputs (EDR connectors, scan data) reflect that
instance's own data — if it has no EDR connectors or no scan coverage, the run says so
(runs against a tenant without connectors fall back to simulated EDR, labeled; runs
without scan coverage report the coverage gap).

The scripts take the instance per call (`--from-mcp <server>`), so a single-instance
run is one script invocation per step. When reporting results, name the instance in the
run summary and the dashboard footer so provenance is explicit.

## Phase 0 — Preflight

### 0.1 Tenable One source

Needs a Tenable MCP server with Exposure Management (tools prefixed `tenable_one_`).
If only VM tools are present, stop and say so.

### 0.2 Firewall source — ask, detect, then fall back

> **Did you know?** This skill can read your firewall's live policy — not just a demo —
> when your firewall vendor's MCP server is connected to this session. Most major
> vendors ship one: Fortinet (FortiManager/FortiGate), Palo Alto Networks, Check Point,
> Cisco and others all have MCP servers that expose firewall policies, interfaces/zones,
> and address/service objects. If you connect yours (see step 3 below for how), this
> skill evaluates your attack paths against your *actual* rulebase instead of a
> simulation — that is the production use of this skill. When no vendor MCP is
> connected, the skill still runs fully: against an exported `--rules` file, or in
> clearly-labeled demo mode.

**Ask the user first** (or accept from the invocation):

1. **Which firewall vendor** do they want to validate against? (Fortinet FortiGate,
   Palo Alto Networks, Check Point, Cisco, other, or "no live firewall — demo mode".)
2. **Is that vendor's MCP server connected to this session?** Look for its tools; if
   connected, use them and adapt the data into the normalized model
   (`references/firewall-model.md`). Vendor support status is stated honestly:
   FortiGate = fully supported (reference implementation); other vendors = supported
   through the normalized model as long as their MCP exposes policies/interfaces/zones,
   with adapter gaps (NAT, security profiles, vendor zone models) called out in the run.
3. **If the vendor MCP is not connected**, prompt with configuration instructions — the
   general form is `claude mcp add <server-name> -- <command>` per the vendor's MCP
   documentation (do not invent package names; point the user at the vendor's docs or
   marketplace listing) — and offer the two fallbacks.

Fallbacks, in order:

1. **Imported rulebase** — any JSON in the normalized model via `--rules`.
2. **Simulated FortiGate MCP server** (`simulator/fortigate_mcp_server.py`) — for
   demos/testing only. **Simulation is opt-in-only (`--simulate`) and is never a silent
   default**: if a vendor MCP or a `--rules` file is available, the skill refuses the
   simulator unless the user explicitly passes `--simulate` or confirms demo mode. This
   prevents accidentally presenting seeded rulebase data to a real customer. When used,
   the dashboard header and the run summary must state that the firewall data is
   simulated.

Always state in the dashboard header and to the user which firewall source was used, and
mark simulated data as such.

### 0.3 Attack-path topology

The MCP `tenable_one_search_assets/findings` tools return only a reduced projection and no
topology. The real attack-path graph comes from REST (verified endpoint):

```
POST https://cloud.tenable.com/api/v1/t1/apa/top-attack-paths/search?limit=1000&offset=0&exclude_resolved=true
```

- Page size **must be ≥ 100** (the API rejects smaller pages with HTTP 400).
- `X-ApiKeys` header; keys can be read in-process from the MCP server entry in
  `~/.claude.json` (same mechanism as the choke-point skill's `--from-mcp`).
- `paths/search` / `attack-paths/search` return 403 on inventory-scoped keys — probe
  `top-attack-paths/search` specifically before concluding topology is unavailable.
- Node `asset_id`s may not match inventory UUIDs for some nodes; join on name as fallback.

## Phase 1 — Scope

1. **Instance** — the single connected Tenable One instance (no question when only one
   is connected). Multiple instances only if the user opts in (see Phase 0.0).
2. **Firewall source** — vendor MCP (asked in Phase 0.2) / `--rules` file / simulator
   (opt-in only, `--simulate` or explicit user confirmation of demo mode).
3. **Zone mapping** — `asset_zone_rules` in the rulebase config map Tenable assets (by name,
   suffix regex, or subnet CIDR) to firewall zones. Review with the user; unmapped endpoints
   are excluded and reported.
4. **Depth** — `quick` (top ~1,000 paths) or `full` (paginate everything).

## Phase 2 — Correlate

Run `scripts/correlate.py` (stdlib-only):

**Optional but recommended — real EDR data.** Two paths, MCP-first:

**MCP path (preferred in-session):** for each vendor in the user's EDR list, call
`tenable_one_search_assets` with filters `[asset_class = DEVICE, sources = [VENDOR]]`,
`limit=200` (paginate with `offset` if `total` > 200). The API matches `sources`
**exactly** (`contains` is silently ignored) — probe spelling variants when a vendor
returns 0 (e.g. `SentinelOne` verified; try `CrowdStrike`/`Crowdstrike`). Report
zero-match vendors loudly. Then write `output/edr_map.json`:
`{"by_hostname": {name_lower: vendor}, "by_asset_id": {asset_id_lower: vendor}}`.

**Script fallback (pipeline):** `python3 scripts/build_edr_map.py --from-mcp <instance>`
does the same over REST for standalone runs.

Then pass `--edr-map output/edr_map.json` to correlate: the map is authoritative —
endpoints not in it have no EDR (never mixed with simulated coverage). Without a map,
the dashboard footer labels EDR as simulated — always.

- **Observed services (recommended):** resolve unknown-port exploit hops using the
  target's own scan evidence. Primary path — the supported `/vulns/export` endpoint
  (Tenable's official replacement for the deprecated Workbench Export):
  - `python3 scripts/fetch_vuln_export_services.py --from-mcp <vm-instance>` runs
    `POST /vulns/export` → polls status → downloads chunks → builds
    `output/observed_services.json` directly from the records (asset + port
    {port, protocol, service} + plugin). Verified: 2,811 records → 38 hosts, 2,119
    service records on a lab tenant.
  - Alternatives when useful: `fetch_scan_services.py` exports recent completed scans
    as `.nessus` (broader coverage in some tenants — REST `/scans` lists only the API
    user's own scans, pass `--scan-ids` for shared ones), and `parse_vm_services.py`
    parses any `.nessus` file directly.
  - For IP-only keys, bridge to names via `tenable_one_search_assets` with an
    `ipv4_addresses contains <ip>` filter (fine for ≤~25 IPs; use
    `scripts/enrich_service_names.py` for larger sets).
  - **Never use the Workbench Export endpoint** (`/workbenches/export`,
    `workbenches_export_workbenches`): deprecated November 2023, permanently removed
    **2027-02-01**. Its replacements are `/vulns/export` and `/assets/export`.
  Pass `--services output/observed_services.json` to correlate. The engine reports
  scan coverage of attack-path targets and warns loudly when it is missing — that
  warning is itself an actionable finding ("scan your attack-path estate").
- Extracts network-relevant hops from the APA dump (`extract_hops.py` in the project's
  scripts folder, or inline equivalent): technique families map to protocol/ports —
  RDP→3389, WinRM→5985/5986, SMB→445, WMI/DCOM/DCSync/Scheduled Task→135, Kerberos
  auth→88/464; `Exploitation of Remote Services` leaves the port unknown (0).
- Evaluates every hop against the rulebase: first enabled policy whose src/dst zone,
  address match (objects + groups + CIDR containment, plus `<zone>-all` covering the
  whole zone) and service (protocol + ports) all match wins.
- **Provable-only semantics**: a hop is ALLOWED/DENIED only by a named rule whose service
  covers its known port. `Exploitation of Remote Services` hops (unknown port) get
  UNVERIFIED when a service-specific allow rule exists for the zone pair — they are
  never counted as live; the dashboard presents them as "possible exposure — verify port".
  Only ALL-service rules give named verdicts for unknown-port hops.
- Identity-only nodes (Group/Domain/Forest/ActiveDirectory with no device label) are
  classified NO_NETWORK and excluded.
- Path verdict: **LIVE** (all applicable hops allowed), **BLOCKED** (≥1 hop denied or
  implicit-deny), **UNMAPPED**, **PARTIALLY_VERIFIED**.

## Phase 3 — Dashboard

`scripts/build_dashboard.py` renders `output/correlation.json` into
`firewall-paths-dashboard-<instance>.html`: exec tiles + headline, zone traffic matrix,
live-path urgency list (priority-ranked), blocked-path groups by control, rule impact
table, **remediation what-if simulator** (each candidate policy change re-runs the full
correlation — deltas are computed by replaying the hop engine, not estimated), and a
remediation focus table. Tenable-branded, dark-first, no external dependencies.

Alongside the HTML, each run writes the remediation tickets as files —
`<dashboard>_tickets.md` (Jira-flavored markdown) and `…_tickets.csv`
(system-agnostic) — ready for manual filing in any ticketing system.

## Phase 4 — Report honestly

Tell the user, every run:

1. Which firewall source was used (live vendor MCP / simulated / imported).
2. How many endpoints mapped to zones vs excluded (NO_ZONES), with examples.
3. That hop ports are *inferred from technique families* — a DENIED verdict for an
   unknown-port exploit hop is conservative, not proof.
4. That this validates *policy as configured*, not as bypassed (rule shadowing,
   NAT, IPv6, routing asymmetry are out of scope).
