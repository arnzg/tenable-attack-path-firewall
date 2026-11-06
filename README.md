# Firewall-Aware Attack Path Validation

A Claude Code skill for the **Tenable CyberAgents Exchange** that joins two sources of
truth: **Tenable One attack-path analysis** (what an attacker *could* do) and your
**firewall policy** (what they *can actually reach*).

Every network-relevant attack-path hop is evaluated against the firewall rulebase under
first-match-wins / default-deny semantics. The result, in one self-contained HTML dashboard:

- **Overstated risk** — attack paths the firewall already cuts, grouped by the control
  that stops them. Stop chasing these.
- **True exposure** — attack paths that survive the rulebase, ranked by APA priority.
  Patch here, or tighten the policy that lets them through.
- **Rule impact** — which policies carry the traffic: allow counts, implicit-deny counts.

## Firewall sources

| Source | When | Notes |
|--------|------|-------|
| Vendor MCP server (FortiGate, Palo Alto, …) | production | Adapted to the normalized model |
| Simulated FortiGate MCP server | demo / testing | `simulator/fortigate_mcp_server.py` — **clearly labeled simulated** |
| Imported JSON rulebase | no MCP | normalized model, `references/firewall-model.md` |

## Quick start

```bash
# 1. Fetch the attack-path topology (keys via the connected MCP server entry)
python3 scripts/fetch_and_correlate.py --from-mcp tenable-one

# 1b. (Recommended) build a real EDR map from 3rd-party connector sources
python3 scripts/build_edr_map.py --from-mcp tenable-one
#    then add --edr-map output/edr_map.json to the correlate step

# 2. Build the dashboard
python3 scripts/build_dashboard.py --instance tenable-one
```

Simulated firewall (for demos):

```bash
claude mcp add fortigate-mock -- python3 "$(pwd)/simulator/fortigate_mcp_server.py"
```

## Requirements

- Tenable One / Exposure Management MCP server with populated Attack Path Analysis.
- Python 3.9+ (stdlib only — no pip dependencies).

## Limitations (state these every run)

- Firewall data in demo mode is **simulated** and seeded to the lab topology.
- Hop ports are inferred from technique families; exploit-port-unknown hops are
  conservatively cut by default deny.
- Zone assignment is name/label/CIDR derived; unmapped endpoints are excluded and reported.
- Validates policy *as configured* — not bypassed rules, NAT, IPv6, or routing asymmetry.

## License

MIT — see LICENSE.
