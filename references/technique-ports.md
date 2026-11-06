# Technique → Port/Protocol Mapping

The APA technique names on each hop are mapped to the network service an attacker would
use. This drives the firewall evaluation. Adjust per environment if needed.

## Mapped families (confirmed from APA technique names)

| Technique family | Protocol | Ports | Notes |
|---|---|---|---|
| Remote Desktop Protocol | tcp | 3389 | |
| Windows Remote Management | tcp | 5985, 5986 | |
| SMB/Windows Admin Shares | tcp | 445 | |
| Services Registry Permissions Weakness | tcp | 445 | SMB-remoted registry |
| Services File Permissions Weakness | tcp | 445 | |
| Windows Management Instrumentation | tcp | 135 (+dynamic) | WMI over DCOM/RPC |
| Distributed Component Object Model | tcp | 135 (+dynamic) | |
| Scheduled Task | tcp | 135 (+dynamic) | atsvc over RPC |
| DCSync | tcp | 135 (+dynamic 49152+) | DRSUAPI over RPC endpoint mapper |
| Domain Controller Authentication | tcp | 88, 464 | Kerberos AS/TGS + kpasswd |
| Domain Accounts | tcp | 88, 464 | Kerberos |
| Exploitation of Remote Services | tcp | **unknown (0)** | plugin-dependent; engine treats as unknown-port hop |

## Unknown-port hops

`Exploitation of Remote Services` hops carry no reliable port. Engine semantics
(**provable-only** — never guess exposure):

- An allow rule matching the zone pair **with the ALL service** → ALLOWED (named rule).
- A deny rule with the ALL service → DENIED (named rule).
- Otherwise → **UNVERIFIED**: the hop hits an allow rule (the `would_allow` field lists
  which) whose service set *may* carry the exploit's port. UNVERIFIED hops are never
  counted as live. Path verdict: PARTIALLY_VERIFIED — "possible exposure: verify the
  exploit's port, then patch or tighten the policy it reaches."
- If no rule at all matches the zone pair → falls through to default deny (IMPLICIT).

Note: APA technique names of the form `Name-<srcNode>:<dstNode>` encode **node IDs,
not ports** (verified on the APA lab data) — do not parse them as ports.

## Out of network scope (excluded, classified NO_NETWORK)

Technique families that traverse identity planes rather than routed networks:
Abuse Elevation Control Mechanism, Domain Groups, LSASS Memory, Network Sniffing,
Password Spraying, NTDS, Local Groups, Windows Credential Manager — and any hop whose
nodes carry identity-only labels (Group, Domain, Forest, ActiveDirectory without a
device label).
