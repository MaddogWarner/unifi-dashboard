# UniFi API Reference

Empirically verified against: **UDR 5G Max, UniFi OS 5.1.12, Network 10.4.57**

---

## Authentication

All requests use a header-based API key — no session cookie or Bearer token.

```
X-API-KEY: <key>
```

Key is generated at: UniFi Network → Settings → Control Plane → Integrations.

SSL verification can be disabled (`verify=False`) for self-signed certificates.

---

## Base URL patterns

| Label | Pattern | Notes |
|-------|---------|-------|
| v1 REST | `https://{host}/proxy/network/api/s/{site}/rest/` | Main data CRUD API |
| v1 stat | `https://{host}/proxy/network/api/s/{site}/stat/` | Read-only statistics |
| v2 integration | `https://{host}/proxy/network/integration/v1/sites/{site}/` | Official public API, limited write surface |
| v2 internal | `https://{host}/proxy/network/v2/api/site/{site}/` | Internal UI API — not officially documented |

`site` defaults to `default`. The v2 integration API also uses a UUID site identifier
(`88f7af54-98f8-306a-a1c7-c9349722b1f6` on this device), but the string `default` works
for all v2 internal paths.

---

## Response formats

**v1 REST:** JSON envelope
```json
{ "meta": { "rc": "ok" }, "data": [ ... ] }
```

**v2 integration:** JSON envelope with pagination
```json
{ "offset": 0, "limit": 25, "count": 2, "totalCount": 2, "data": [ ... ] }
```

**v2 internal:** Raw array or object (no envelope)
```json
[ ... ]
```

**v1 error (unknown collection):**
```json
{ "meta": { "rc": "error", "msg": "api.err.InvalidObject" }, "data": [] }
```
HTTP status is **400**, not 404. `InvalidObject` means the collection does not exist on
this firmware — treat as "endpoint unavailable".

---

## Confirmed working endpoints

### Zones
```
GET /proxy/network/v2/api/site/{site}/firewall/zone
```
Returns raw list. Each zone object:
```json
{
  "_id": "69dcb6b9fad2982437fb1a8d",
  "name": "Internal",
  "zone_key": "internal",
  "default_zone": true,
  "attr_no_edit": false,
  "external_id": "a2b15ecc-7e49-4bd1-9021-efe09256877b",
  "network_ids": ["69dc9cc9999eba3de48f5d1f"],
  "cloud_template": null
}
```
Zones on this device: Internal, External, Gateway, Vpn, Hotspot, Dmz, IoT Smart Home (custom).
Custom zones have `zone_key: null` and `default_zone: false`.
The `_id` field is the MongoDB ObjectID used for all cross-references.

### Networks / VLANs
```
GET /proxy/network/api/s/{site}/rest/networkconf
```
v1 REST envelope. Key fields per network:
```json
{
  "_id": "69dc9cc9999eba3de48f5d1f",
  "name": "Secured Network",
  "purpose": "corporate",
  "networkgroup": "LAN",
  "firewall_zone_id": "69dcb6b9fad2982437fb1a8d"
}
```
`firewall_zone_id` cross-references the zone `_id` from the zone endpoint above.
WAN networks have `purpose: "wan"` and no `networkgroup`; use `wan_networkgroup` instead (WAN, WAN2, WAN3).

Also available via v2 integration (returns UUID-format `zoneId` instead of MongoDB `firewall_zone_id`):
```
GET /proxy/network/integration/v1/sites/{site}/networks
```

### Firewall groups (IP/port lists)
```
GET    /proxy/network/api/s/{site}/rest/firewallgroup
POST   /proxy/network/api/s/{site}/rest/firewallgroup
PUT    /proxy/network/api/s/{site}/rest/firewallgroup/{id}
DELETE /proxy/network/api/s/{site}/rest/firewallgroup/{id}
```
Group types: `address-group`, `ipv6-address-group`, `port-group`.

Create payload:
```json
{
  "name": "ThreatFeed-External-0",
  "group_type": "address-group",
  "group_members": ["1.2.3.4", "5.6.7.8"]
}
```
Returns created object in `data[0]`. `_id` is assigned by UniFi.

On POST with a name that already exists, UniFi returns 400. The application should
GET groups and reuse the existing one rather than failing.

### Classic firewall rules
```
GET    /proxy/network/api/s/{site}/rest/firewallrule
POST   /proxy/network/api/s/{site}/rest/firewallrule
PUT    /proxy/network/api/s/{site}/rest/firewallrule/{id}
DELETE /proxy/network/api/s/{site}/rest/firewallrule/{id}
```
Classic rules are **not visible** in the Network 10 Policy Engine UI but **are enforced**
at the iptables/nftables level on the gateway. Use them when zone-based policy creation
is unavailable (see below).

Rule rulesets: `WAN_IN`, `WAN_LOCAL`, `LAN_IN`, `LAN_OUT`, `LAN_LOCAL`, `GUEST_IN`.

Create payload example (block source IP group on WAN_IN):
```json
{
  "name": "Block-ThreatFeed-External-0",
  "enabled": true,
  "ruleset": "WAN_IN",
  "rule_index": 20000,
  "action": "drop",
  "protocol": "all",
  "src_firewallgroup_ids": ["<group_id>"],
  "dst_firewallgroup_ids": [],
  "logging": true,
  "state_established": false,
  "state_invalid": false,
  "state_new": false,
  "state_related": false
}
```

### Traffic rules (v2 internal)
```
GET    /proxy/network/v2/api/site/{site}/trafficrules
POST   /proxy/network/v2/api/site/{site}/trafficrules
```
Returns raw array. Empty on this device (no traffic rules configured). Structure TBD —
these are traffic management rules, not firewall rules. Suitable for client access control,
not inbound IP blocking.

### Sites (v2 integration)
```
GET /proxy/network/integration/v1/sites
```
Returns pagination envelope. Useful for connectivity checks. `internalReference` field
contains the string site name (`default`); `id` is the UUID.

### Devices
```
GET /proxy/network/v2/api/site/{site}/device
```
Returns raw array of UniFi devices.

### Settings
```
GET /proxy/network/api/s/{site}/rest/setting
```
Returns all site settings as a list. Available setting keys include: `connectivity`,
`usg`, `ugw`, `ips`, `doh`, `rsyslogd`, `global_switch`, `global_nat`, `ssl_inspection`,
`openvpn`, `ipsec`, `snmp`, and others. Individual settings accessible at:
```
GET /proxy/network/api/s/{site}/rest/setting/{key}
```

### IDS/IPS config
```
GET /proxy/network/api/s/{site}/rest/setting/ips
```

### Alerts
```
GET /proxy/network/v2/api/site/{site}/alert
```

---

### Zone-based firewall policies (v2 internal)
```
GET    /proxy/network/v2/api/site/{site}/firewall-policies
POST   /proxy/network/v2/api/site/{site}/firewall-policies
PUT    /proxy/network/v2/api/site/{site}/firewall-policies/{id}
DELETE /proxy/network/v2/api/site/{site}/firewall-policies/{id}
```
Returns raw array (GET) or raw object (POST/PUT). No envelope.

**Key field requirements (confirmed via on-device POST test):**
- All enum values are **uppercase**: `"BLOCK"`, `"ALLOW"`, `"IPV4"`, `"IPV6"`, `"BOTH"`, `"IP"`, `"SPECIFIC"`, `"ANY"`, `"ALWAYS"`
- `source.ips` contains IP addresses **directly** — no firewall group reference
- `source.matching_target`: `"IP"` for specific IPs, `"ANY"` for wildcard
- `source.matching_target_type`: `"SPECIFIC"` when using explicit IPs
- Both `source` and `destination` require a `zone_id` — no wildcard zone

Minimal working POST payload (block specific IPs from External zone to DMZ):
```json
{
  "name": "Block-ThreatFeed-Dmz-0",
  "enabled": true,
  "action": "BLOCK",
  "ip_version": "IPV4",
  "protocol": "all",
  "connection_state_type": "ALL",
  "connection_states": [],
  "create_allow_respond": false,
  "match_ip_sec": false,
  "match_opposite_protocol": false,
  "logging": true,
  "icmp_typename": "ANY",
  "icmp_v6_typename": "ANY",
  "schedule": {"mode": "ALWAYS"},
  "source": {
    "zone_id": "<external_zone_id>",
    "matching_target": "IP",
    "matching_target_type": "SPECIFIC",
    "match_opposite_ips": false,
    "match_opposite_ports": false,
    "port_matching_type": "ANY",
    "ips": ["1.2.3.4", "5.6.7.8"]
  },
  "destination": {
    "zone_id": "<dest_zone_id>",
    "matching_target": "ANY",
    "match_opposite_ports": false,
    "port_matching_type": "ANY"
  }
}
```

Returns the created policy object with `_id` assigned by UniFi.

DELETE returns HTTP 204 (no body).

For threat-feed bidirectional blocking, create a second policy with the same IP
list on the destination side instead of the source side:

- inbound: `source.zone_id = External`, `source.ips = threat IPs`, `destination.zone_id = Dmz`
- outbound: `source.zone_id = Dmz`, `destination.zone_id = External`, `destination.ips = threat IPs`

**Important:** Firewall groups (`/rest/firewallgroup`) are **not** referenced by zone policies.
IPs must be embedded directly in `source.ips`. Groups are only used by classic rules (`/rest/firewallrule`).

---

## Confirmed unavailable endpoints (Network 10.4.57)

| Endpoint | HTTP status | Notes |
|----------|-------------|-------|
| `/proxy/network/api/s/{site}/rest/zone` | 400 InvalidObject | Use v2 internal firewall/zone instead |
| `/proxy/network/integration/v1/sites/{site}/firewall-zones` | 404 | Not implemented on this firmware |
| `/proxy/network/integration/v1/sites/{site}/firewall-policies` | 404 | Not implemented |
| `/proxy/network/api/s/{site}/rest/firewallpolicy` | 400 InvalidObject | Zone policy collection does not exist |
| `/proxy/network/v2/api/site/{site}/firewall/policy` | 404 | Not implemented |
| `/proxy/network/api/s/{site}/rest/trafficrule` | 400 InvalidObject | Use v2 trafficrules path instead |
| `/proxy/network/api/s/{site}/stat/event` | 404 | IPS events not available via this path |
| `/proxy/network/api/s/{site}/rest/portforwardingrule` | 400 InvalidObject | |

---

## Zone-based policy creation

**Not possible via any known API on Network 10.4.57.** The `/rest/firewallpolicy` collection
returns HTTP 400 (InvalidObject), indicating the endpoint does not exist on this firmware.
All v2 integration and internal write paths for policies also return 404.

The Policy Engine UI manages zone policies internally through mechanisms that are not exposed
via the public or semi-public API surface. Classic firewall rules remain the only writable
enforcement mechanism.

**Workaround:** Classic rules (`/rest/firewallrule`) target v1 rulesets (`WAN_IN`, `LAN_IN`,
etc.) which map to zones as follows:

| v1 ruleset | Zone equivalent |
|------------|----------------|
| `WAN_IN` | External (inbound from internet) |
| `WAN_LOCAL` | External (to gateway itself) |
| `LAN_IN` | Internal (inter-VLAN / from LAN) |
| `LAN_LOCAL` | Internal (to gateway from LAN) |
| `LAN_OUT` | Internal (outbound from LAN) |
| `GUEST_IN` | Hotspot / Guest |

---

## ID formats

Two ID formats exist and are not interchangeable:

| Format | Example | Used in |
|--------|---------|---------|
| MongoDB ObjectID (24-char hex) | `69dcb6b9fad2982437fb1a8d` | v1 REST `_id` fields, zone `_id`, all cross-references |
| UUID | `a2b15ecc-7e49-4bd1-9021-efe09256877b` | v2 integration `id` / `zoneId` fields |

The MongoDB ObjectID is the authoritative identifier for cross-referencing between v1 objects.
The UUID is the `external_id` on zone objects and the `id` on v2 integration network objects.
They refer to the same entities but cannot be used interchangeably across API versions.
