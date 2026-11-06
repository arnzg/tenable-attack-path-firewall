# Firewall Rule Data Model (vendor-neutral core)

Every firewall source — the mock FortiGate MCP server now, a real FortiManager
or Palo Alto MCP later — is normalized into this model by a thin adapter.
The correlation engine only ever sees this model.

## Rule

```json
{
  "rule_id": "FW-POL-014",            // vendor rule id/uid
  "name": "Allow-Web-To-DMZ",
  "src_zone": "external",             // zone name; "any" allowed
  "dst_zone": "dmz",
  "src": ["any"],                     // address objects: IPs, CIDRs, names
  "dst": ["dmz-web-01", "10.20.0.10/32"],
  "service": ["HTTPS", "HTTP"],      // service objects: names or port/protocol
  "action": "allow",                  // "allow" | "deny" | "reset"
  "log": true,
  "enabled": true,
  "nat": null,
  "comment": "",
  "device": "edge-fw-01",             // which firewall in the estate
  "raw_vendor": { ... }               // untouched vendor object for audit
}
```

## Address object
```json
{ "name": "dmz-web-01", "type": "host"|"network"|"fqdn"|"range", "value": "10.20.0.10" }
```

## Service object
```json
{ "name": "RDP", "protocol": "tcp", "ports": [3389] }
```

## Zone
```json
{ "name": "internal", "interfaces": ["port3"], "subnets": ["10.10.0.0/16"] }
```
Zones are the join key to Tenable assets: each Tenable DEVICE asset is mapped
to a zone in the firewall simulation config (e.g., dc1/dc2 -> "core",
win11 fleet -> "internal", testfire apps -> "dmz", truenas -> "storage").

## Correlation semantics
- A hop (src asset -> dst asset, technique => port/protocol/service) is
  evaluated against the rulebase in top-down order (first match wins,
  like FortiGate).
- Verdicts per hop:
  - ALLOWED     — an enabled allow rule matches (path hop is real)
  - DENIED      — an enabled deny rule matches (path hop is cut)
  - IMPLICIT    — no rule matches and device default-deny -> cut
  - NO_ZONES    — src/dst asset not mapped to firewall zones (unknown)
  - NO_NETWORK  — identity-only hop (account/group/identity edges);
                  firewall not applicable
- Path verdict: weakest meaningful hop wins (NO_NETWORK hops are skipped;
  a path is LIVE only if all applicable hops are ALLOWED).
