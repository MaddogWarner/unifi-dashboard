# Roadmap

Items 4 and 7 were pulled into the threat-feed hit correlation and assessment history plan on
14 July 2026.

Feature ideas from the July 2026 codebase review, not yet built. Numbering carried over from
that review (items 1–3 — data retention, notifications, Prometheus metrics — shipped in
[v2.1.0](https://github.com/MaddogWarner/unifi-dashboard/releases/tag/v2.1.0)).

This is a backlog of ideas, not a commitment or a schedule. Pull an item into `codex-plan.md`
when it's ready to build.

---

## 4. Threat-feed hit correlation

Close the loop already built: the dashboard ingests blocklists and pushes `Block-ThreatFeed-*`
rules, and separately parses syslog block events with rule names. Cross-reference them —
"FireHOL Level 1 blocked 214 connection attempts this week, top source 45.x.x.x." Turns the
experimental threat-feed feature from "clutter risk" into something with visible, provable
value, and it's mostly a query over data already stored.

## 5. Firewall log analytics + GeoIP

The Logs tab is a paginated firehose. Add aggregate views: top blocked source IPs, top targeted
ports, events-over-time chart, and GeoIP country enrichment (MaxMind GeoLite2 works offline — no
egress needed). Optionally a click-through AbuseIPDB/VirusTotal lookup per IP.

## 6. Scheduled scans with diffing

The scanner is on-demand only. Add a configurable schedule (e.g. weekly scan of gateway + key
hosts) and diff against the previous result — "port 8080 newly open on 192.168.1.50" becomes an
attention-feed item and a notification. Turns the scanner from a manual tool into continuous
validation. The RFC1918 guard stays untouched.

## 7. Assessment score history

The 10 checks run constantly but no history is kept. Persist each run (score + per-check
status), chart the trend on the Assessment page, and alert on regressions ("score dropped
85 → 70 after last policy change"). Pairs naturally with drift snapshots — answers which change
hurt the score.

## 8. New-device detection

`stat/device` is already called for CVE matching; adding `stat/sta` (clients) gives "unknown MAC
joined the IoT VLAN at 02:14" — one of the most useful home-network security signals there is.
Inventory table with first-seen/last-seen, VLAN, and a known/unknown flag feeding the attention
feed.

## 9. Expand the assessment checks

The current 10 are policy-focused. UniFi's API exposes enough for: UPnP enabled (big one), WiFi
security posture (open SSIDs, WPA2 vs WPA3, default guest portal), remote/cloud access enabled on
the console, and console firmware currency. Each is an independent, small check in
`services/api/app/services/assessment.py`.

## 10. AdGuard integration (specific to this deployment)

AdGuard Home runs on the same Pi. Its API exposes blocked DNS queries — correlating DNS-layer
blocks with firewall-layer blocks per client would give a per-device security view no
off-the-shelf tool offers. More speculative, but uniquely suited to this deployment.

---

## MCP additions to consider alongside any of the above

- `get_assessment_history` — pairs with item 7
- `get_top_blocked_sources` — pairs with item 4
- `acknowledge_cve` — first write-tool the MCP server would expose; needs care
- An MCP *resource* exposing the attention feed, so Claude Code sessions start with current
  posture context without an explicit tool call
