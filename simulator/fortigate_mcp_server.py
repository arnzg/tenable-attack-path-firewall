#!/usr/bin/env python3
"""Simulated FortiGate MCP server (stdio transport, MCP 2.0 JSON-RPC).

Emulates a FortiGate firewall's management surface for demo/testing of the
Firewall-Aware Attack Path Validation skill. Loads its rulebase from
fortigate_lab_rules.json next to this script.

Run:  python3 fortigate_mcp_server.py            (register with:
      claude mcp add fortigate-mock -- python3 /path/to/fortigate_mcp_server.py)

Tools (FortiGate-flavored):
  get_system_status            - device info
  list_interfaces              - interfaces / zones
  list_firewall_policies       - paginated policy table (optional name filter)
  get_firewall_policy          - single policy by id or name
  list_address_objects         - address objects + groups
  list_service_objects         - service objects
  get_policy_hitcount          - deterministic hit counters per policy
Stdlib only. No secrets. Safe: read-only simulation.
"""
import json, os, sys, zlib, base64

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "fortigate_lab_rules.json")

RULES = json.load(open(RULES_PATH))
PROTO = "2024-11-05"

TOOLS = [
    {"name": "get_system_status", "description": "FortiGate device info: hostname, model, FortiOS version, VDOMs.",
     "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "list_interfaces", "description": "List physical interfaces with zones (srcintf/dstintf values) and IPs.",
     "inputSchema": {"type": "object", "properties": {"zone": {"type": "string", "description": "Filter by zone name"}}, "required": []}},
    {"name": "list_firewall_policies", "description": "List firewall policies in evaluation order (first match wins). Optional filter by name substring or action.",
     "inputSchema": {"type": "object", "properties": {
         "filter_name": {"type": "string"}, "action": {"type": "string", "enum": ["allow", "deny"]},
         "limit": {"type": "integer", "default": 50}, "offset": {"type": "integer", "default": 0}}, "required": []}},
    {"name": "get_firewall_policy", "description": "Get one policy by numeric id or name.",
     "inputSchema": {"type": "object", "properties": {"policy_id": {"type": "integer"}, "name": {"type": "string"}}, "required": []}},
    {"name": "list_address_objects", "description": "FortiGate address objects and address groups.",
     "inputSchema": {"type": "object", "properties": {"include_groups": {"type": "boolean", "default": True}}, "required": []}},
    {"name": "list_service_objects", "description": "FortiGate service objects (protocol + ports).",
     "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_policy_hitcount", "description": "Deterministic simulated hit counters per policy id.",
     "inputSchema": {"type": "object", "properties": {"policy_id": {"type": "integer"}}, "required": []}},
]

def resolve_group(name, seen=None):
    seen = seen or set()
    if name in seen: return []
    seen.add(name)
    out = []
    for member in RULES.get("address_groups", {}).get(name, []):
        if member in RULES.get("address_groups", {}):
            out += resolve_group(member, seen)
        else:
            out.append(member)
    return out or [name]

def tool_get_system_status(_args):
    return RULES["device"]

def tool_list_interfaces(args):
    zone = (args or {}).get("zone")
    items = RULES["interfaces"]
    if zone:
        items = [i for i in items if i["zone"] == zone]
    return {"count": len(items), "interfaces": items}

def tool_list_firewall_policies(args):
    args = args or {}
    items = RULES["policies"]
    if args.get("filter_name"):
        fl = args["filter_name"].lower()
        items = [p for p in items if fl in p["name"].lower()]
    if args.get("action"):
        items = [p for p in items if p["action"] == args["action"]]
    total = len(items)
    off, lim = int(args.get("offset", 0)), int(args.get("limit", 50))
    return {"total": total, "offset": off, "count": len(items[off:off+lim]),
            "policies": items[off:off+lim],
            "default_deny": RULES.get("default_deny", True)}

def tool_get_firewall_policy(args):
    args = args or {}
    for p in RULES["policies"]:
        if ("policy_id" in args and p["id"] == args["policy_id"]) or \
           ("name" in args and p["name"].lower() == args["name"].lower()):
            return p
    return {"error": "policy not found"}

def tool_list_address_objects(args):
    out = {"count": len(RULES["addresses"]), "addresses": RULES["addresses"]}
    if (args or {}).get("include_groups", True):
        out["groups"] = [{"name": g, "members": resolve_group(g)}
                         for g in RULES.get("address_groups", {})]
    return out

def tool_list_service_objects(_args):
    return {"count": len(RULES["services"]), "services": RULES["services"]}

def tool_get_policy_hitcount(args):
    pid = (args or {}).get("policy_id")
    hits = {}
    for p in RULES["policies"]:
        h = zlib.crc32(p["name"].encode()) % 100000 + 50
        hits[str(p["id"])] = {"name": p["name"], "hits": h}
    if pid is not None:
        return hits.get(str(pid), {"error": "unknown policy"})
    return {"policies": hits}

HANDLERS = {
    "get_system_status": tool_get_system_status,
    "list_interfaces": tool_list_interfaces,
    "list_firewall_policies": tool_list_firewall_policies,
    "get_firewall_policy": tool_get_firewall_policy,
    "list_address_objects": tool_list_address_objects,
    "list_service_objects": tool_list_service_objects,
    "get_policy_hitcount": tool_get_policy_hitcount,
}

def reply(msg_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()

def dispatch(method, params):
    if method == "initialize":
        return {"protocolVersion": PROTO,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fortigate-mock", "version": "1.0.0"}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        fn = HANDLERS.get(name)
        if not fn:
            return {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True}
        return {"content": [{"type": "text", "text": json.dumps(fn(args), indent=2)}], "isError": False}
    if method == "ping":
        return {}
    return None  # notifications: no response

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = req.get("method", "")
        if method.startswith("notifications/"):
            continue
        result = dispatch(method, req.get("params") or {})
        if result is not None:
            reply(req.get("id"), result)

if __name__ == "__main__":
    main()
