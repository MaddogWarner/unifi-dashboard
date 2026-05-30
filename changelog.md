# Changelog

All notable project changes are recorded here.

## Unreleased - 2026-05-30

### Added

- Added a global threat-feed direction mode setting with `inbound` default and `bidirectional` option. Bidirectional mode keeps existing External-to-zone block policies and adds matching zone-to-External outbound block policies with threat-feed IPs matched on the destination side.
- Added rule direction tracking to `threat_feed_rules` and `threat_feed_pending_rules`, including Alembic migration 008, API status output, pending-rule output, settings validation, and Settings/Threat Feeds UI support.

### Fixed

- Restored legacy threat-feed target compatibility for zone-policy enforcement. Saved/default values such as `WAN_IN` and `WAN_LOCAL` are again mapped to valid UniFi destination zones before pending approvals are queued, while real zone names and custom zones are still validated against the live UniFi zone cache.
- Fixed Threat Feeds pending-rule table refresh timing. Manual threat-feed refresh now waits for the collector to complete before returning success, and the pending-rule table polls alongside the status card so asynchronously queued approvals appear without a page reload. Pending-rule API errors are now surfaced inline instead of looking like an empty table.
- Fixed 500 Internal Server Error on the Threat Feeds pending-rule table. Migration 008 used `op.add_column()` which silently does not apply through the asyncpg `run_sync` adapter (same issue as migration 005). The `direction` column was not added to `threat_feed_pending_rules`, causing `GET /api/v1/threatfeed/pending-rules` to fail. Migration 008 rewritten to use `op.execute()` raw SQL throughout (same pattern as migrations 006/007), with all steps made fully idempotent (`ADD COLUMN IF NOT EXISTS`, constraint creation guarded by `IF NOT EXISTS`). An API startup schema guard was also added to `enforce_runtime_schema_guards()` as a belt-and-suspenders fallback that adds the `direction` column immediately on boot if it is still absent.

## Unreleased - 2026-05-29 (session 9)

### Fixed

- Added migration 007 and an API startup schema guard to reassert `threat_feed_rules.group_unifi_id` is nullable even when a deployed database was already stamped past the earlier nullable migration. This prevents zone-policy approvals from creating UniFi policies successfully and then failing during local rule tracking.
- Made threat-feed rule recording store an empty group ID sentinel for zone-policy rows so approval remains compatible with older deployed databases that still have the previous `NOT NULL` constraint until the schema guard has corrected them.
- Added migration 006 using `op.execute()` raw SQL to force `threat_feed_rules.group_unifi_id` nullable. Migration 005's `op.alter_column()` was not reliably committing the DDL through the asyncpg `run_sync` adapter; raw SQL via `op.execute()` bypasses this. The `DROP NOT NULL` statement is idempotent on PostgreSQL, so it is safe to run whether or not migration 005 applied correctly.

## Unreleased - 2026-05-29 (session 8)

### Fixed

- Fixed zone-based firewall policy creation using the wrong API path. All five zone policy functions in `unifi_client.py` (`zone_policy_api_available`, `get_zone_policies`, `create_zone_policy`, `update_zone_policy`, `delete_zone_policy`) were targeting the v1 `/rest/firewallpolicy` path (HTTP 400 on Network 10) and the v2 integration path (HTTP 404). They now use the confirmed v2 internal path `/proxy/network/v2/api/site/{site}/firewall-policies`, constructed from the v1 base URL the same way `get_zones_list()` does.
- Fixed zone policy payload structure. The API embeds IPs directly in `source.ips` — there is no `firewallgroup_ids` field. Firewall groups are only used by classic rules, not zone policies. `_zone_policy_payload()` now builds the correct payload with `source.matching_target: "IP"`, `source.matching_target_type: "SPECIFIC"`, and the IP list in `source.ips`. All enum values are uppercase (`"BLOCK"`, `"IPV4"`, `"ALWAYS"`, etc.) as required by the UniFi API. Zone policies do not use firewall groups at all.
- Made `threat_feed_rules.group_unifi_id` nullable in the SQLAlchemy model and added Alembic migration 005 to `ALTER COLUMN ... DROP NOT NULL`. Zone policies carry no associated firewall group, so `group_unifi_id = None` is valid for zone-policy-enforced rules.
- Fixed zone validation in `_apply_to_unifi()` accepting stale legacy ruleset names (WAN_IN, WAN_LOCAL, DMZ uppercase) as zone destinations. The `RULESET_TO_DEST_ZONE` mapping was removed. Zone names are now validated directly against the live UniFi zone cache populated by `_populate_zone_cache()`, with a warning logged and the zone skipped if the stored name is not a real zone name.
- Fixed null dereference in `_cleanup_unifi_rules()` calling `_delete_firewall_group_if_present(rule.group_unifi_id)` when `group_unifi_id` is `None` for zone-policy rules. Added a guard so the group delete is only attempted when the field is non-null.

### Validation

- UniFi API endpoints confirmed via on-device probe and documented in `api.md`.

## Unreleased - 2026-05-29 (session 7)

### Fixed

- Fixed zone picker showing a static 6-item fallback list (missing custom zones like IoT Smart Home). `/api/v1/networks/zones` now falls back to distinct zone names stored in the `networks` DB table (populated each poll cycle from UniFi network configuration) when the UniFi zone list API returns empty. The Settings page no longer has a hardcoded fallback list — it shows all zones returned by the endpoint or an error message if the connection is unreachable.

## Unreleased - 2026-05-29 (session 6)

### Fixed

- Fixed `get_zones_list()` only catching HTTP 404 — any other error (403, 500, network error) propagated and caused `/api/v1/networks/zones` to return 500, putting the Settings zone picker in error/fallback state. Now catches all HTTP errors (except 4xx other than 404/405 which still propagate as genuine errors) and general exceptions, logging each at DEBUG/WARNING.
- Fixed `get_zones_list()` only trying one API path. Now tries both v1 `/rest/zone` and v2 `/firewall-zones` endpoints, using the first that returns a non-empty list. Ensures zone names are discovered on devices where only one endpoint is available.
- Fixed `_resolve_zone_id()` in the threat feed collector having no fallback when `/rest/zone` is unavailable. Now extracts zone IDs from existing zone-based firewall policies (`/rest/firewallpolicy`) if the zone list API returns empty, enabling zone policy enforcement on devices where the zone list endpoint is absent but policies can still be read.
- Fixed Settings page fallback zone picker showing v1 ruleset names (WAN_IN, WAN_LOCAL, etc.) when zone API is unavailable. Fallback now shows actual UniFi zone names (External, Internal, Gateway, VPN, Hotspot, DMZ) matching the Policy Engine.

## Unreleased - 2026-05-29 (session 5)

### Added

- Added zone-based firewall policy creation for threat feed enforcement. On first run the API probes `/rest/firewallpolicy`; if available, block policies are created in the zone-based Policy Engine (visible and manageable in UniFi → Policy Engine) instead of the legacy classic rules system.
- Added `/rest/zone` querying via `get_zones_list()` in `unifi_client.py`. Zone names and IDs are cached per process for efficient policy creation.
- Added `GET /api/v1/networks/zones` endpoint that returns available UniFi zone names and IDs for the frontend.
- Added dynamic zone picker to the Settings page: zone list is fetched from UniFi at page load, showing actual zone names (e.g. External, Internal, IoT Smart Home) instead of hardcoded v1 ruleset labels. Falls back to the original WAN_IN/WAN_LOCAL/LAN_IN checkbox list if the zone API is unavailable.

### Changed

- `threat_feed.zones` setting now accepts any non-empty string array (previously restricted to fixed v1 ruleset names). The collector maps v1 names to zone names automatically, so existing settings migrate without reconfiguration.
- When zone policies are available, v1 ruleset names (WAN_IN, WAN_LOCAL) are mapped to their zone equivalents and deduplicated before enforcement — WAN_IN + WAN_LOCAL both map to the External zone, creating one policy per chunk instead of two.
- `_cleanup_unifi_rules()` now sweeps orphaned zone policies (prefix `Block-ThreatFeed-`) in addition to classic firewall rules, ensuring complete cleanup on disable.
- Delete path in `_apply_change()` now routes to `delete_zone_policy` vs `delete_firewall_rule` based on whether the stored ruleset key is a v1 name or a zone name, handling the mixed state during migration.

### Validation

- Python syntax validation passed for `unifi_client.py`, `threat_feed_collector.py`, `networks.py`, `settings.py`.
- Frontend production build passed with `npm run build`.

## Unreleased - 2026-05-29 (session 4)

### Fixed

- Fixed assessment endpoint returning HTTP 500 on a database with prior scan results. Pydantic v2 could not validate `AssessmentEvidence` dataclass instances against `AssessmentEvidenceOut` without `from_attributes=True`; added `model_config = ConfigDict(from_attributes=True)` to `AssessmentEvidenceOut` in `schemas/assessment.py`.
- Fixed `stat/event` 404 errors being logged as ERROR on every poll cycle. UDR 5G Max running Network 10.4.57 does not support this endpoint. `get_threat_events()` now catches 404, logs a single WARNING, and returns an empty list — matching the existing graceful degradation pattern used by `get_firewall_policies()` and `get_port_forwards()`.
- Fixed syslog collector flooding logs with WARNING every 100 non-firewall datagrams. The UDR forwards all syslog categories (mDNS, mcad, kernel, systemd), not just firewall events. `_log_unparsed()` now emits one WARNING on first occurrence with an explanatory message, then DEBUG at every 10,000 messages.

### Validation

- Python syntax validation confirmed for `schemas/assessment.py`, `services/unifi_client.py`, and `collectors/syslog.py`.
- All three commits pushed to `origin/main`; CI pipeline will rebuild and publish the API image.

## Unreleased - 2026-05-29 (session 3)

### Fixed

- Skipped `alembic upgrade head` after a successful startup fast-forward to the current Alembic head, preventing deployed databases from re-entering the `004_firewall_port_forwards` upgrade path.
- Added an API startup Alembic fast-forward for existing databases at `003_ids_config_raw_json`, stamping directly to the additive `004_firewall_port_forwards` revision before `upgrade head` so startup no longer executes the problematic revision path on deployed installs.
- Hotfixed API startup blocking during `004_firewall_port_forwards` by making the additive Alembic revision a fast no-op. The optional port-forward table is now created by the existing SQLAlchemy metadata safety net after migrations complete.
- Made assessment generation tolerate an unavailable port-forward evidence table during rollout and continue with scan/WAN-rule evidence instead of failing the full report.
- Added an explicit application startup completion log after background collectors are started.

## Unreleased - 2026-05-29 (session 2)

### Added

- Added structured assessment evidence for the `DMZ for exposed services` check, including host, port, protocol, service, scan ID, source, matching UniFi object, and observed timestamp.
- Added best-effort UniFi v1 port-forward polling from `/rest/portforward` and persisted enabled port-forward metadata for WAN exposure correlation.
- Added Assessment page evidence rows so open ports and likely WAN exposure matches are visible under the affected check.

### Changed

- Improved DMZ assessment wording to distinguish open internal services from services likely exposed through WAN port forwards or WAN allow rules.
- Updated scanner documentation to describe assessment evidence and WAN exposure correlation.

### Validation

- Python syntax validation passed for assessment, poller, UniFi client, model, router, schema, migration, and focused assessment evidence test code.
- Frontend production build passed with `npm run build`.
- `git diff --check` passed.
- Focused pytest execution could not run locally because `pytest` is not installed on PATH.

## Unreleased - 2026-05-29

### Fixed

- Added API startup migration diagnostics and PostgreSQL migration timeouts so Alembic startup failures are visible instead of appearing to hang before syslog and polling tasks start.
- Made the `ids_config.raw_json` Alembic migration idempotent for databases where the column already exists.
- Published API UDP syslog port `${SYSLOG_PORT:-514}` from Docker Compose so UniFi remote logging can reach the receiver.
- Added low-noise syslog diagnostics for first received packet, first parsed firewall event, and unparsed syslog samples.
- Added a Firewall page fallback that shows legacy `/firewall/rules` when v2 zone policies are unavailable or empty.

### Changed

- Firewall empty states now distinguish between missing zone policy data, available legacy rules, and missing syslog events.
- README syslog setup now documents the Docker UDP port mapping check.

### Validation

- Python syntax validation passed for API startup, syslog collector, firewall router, poller, and Alembic migration code.
- Frontend production build passed with `npm run build`.
- Docker Compose validation could not be run locally because Docker is not installed in this environment.

## Unreleased - 2026-05-28 (session 15)

### Fixed

- Fixed IPS prevention-mode detection for UniFi IDS/IPS payloads that report block mode using camelCase or action-style values such as `notifyAndBlock`, `alertAndBlock`, or `block`.
- Expanded IDS mode normalisation to recognise additional UniFi mode fields including `ips_mode`, `protection_mode`, `prevention_mode`, `action_mode`, `security_mode`, and `threat_detection_mode`.

### Validation

- Python syntax validation passed for IDS poller, assessment service, threats router, and IDS normalisation tests.
- Focused IDS normalisation tests could not be run in this local environment because `pytest` is not installed on PATH.

## Unreleased - 2026-05-28 (session 14)

### Fixed

- Fixed API startup failures that could surface as nginx `502 Bad Gateway` after automatic Alembic migrations were added. Existing databases created before Alembic version tracking are now detected and stamped at the appropriate baseline revision before `alembic upgrade head` runs.
- Added defensive baseline detection for databases that already contain the latest `ids_config.raw_json` column but do not yet have an `alembic_version` row, avoiding duplicate-column migration failures.

### Validation

- Python syntax validation passed for API startup and Alembic migration code.

## Unreleased - 2026-05-28 (session 13)

### Fixed

- Added automatic `alembic upgrade head` execution during API startup before `create_all`, preventing schema drift such as missing `ids_config.raw_json` from breaking assessment queries after container updates.
- Fixed threat feed disable cleanup so generated UniFi rules and groups are deleted automatically regardless of preview mode.
- Fixed cleanup of orphaned UniFi threat-feed objects by deleting generated rules with the `Block-ThreatFeed-` prefix and groups with the `ThreatFeed-` prefix, even when local DB tracking rows are missing.
- Fixed threat-feed approval retries returning HTTP 500 after UniFi objects were already created. Approvals now reconcile existing generated UniFi groups/rules by name and upsert the local `(ruleset, chunk_index)` tracking row.
- Added assessment route exception logging and a clear HTTP 500 detail when assessment generation is temporarily unavailable.

### Validation

- Python syntax validation passed for API app, Alembic migrations, and API tests.

## Unreleased - 2026-05-28 (session 12)

### Fixed

- Refactored frontend action overlays to use a global event-driven toast host mounted above routing in `main.tsx`, making success/error notifications independent of route component state.
- Added stable `data-testid="action-toast"` and `data-tone` attributes to make overlay rendering observable in browser devtools and automated checks.
- Added error toasts for save, refresh, and threat feed rule-apply failures so failed API calls are visibly distinct from missing success overlays.

### Changed

- Threat feed approve/reject actions now show success overlays when rules are applied or rejected successfully.

### Validation

- Frontend production build passed with `npm run build`.
- Frontend test command `npm test -- --run` was attempted, but Vitest exited with no test files found.
- Frontend build emitted the existing Vite chunk-size warning; no build failure occurred.

## Unreleased - 2026-05-28 (session 11)

### Fixed

- Fixed IDS/IPS assessment false negatives for UDR 5G Max / UniFi Network 10 style payloads. IDS config polling now normalises newer intrusion-prevention and threat-management field names in snake_case, kebab-case, and camelCase, including `Notify and Block` as IPS prevention mode.
- Added fallback IDS/IPS enablement detection from selected networks, active detections, category data, and legacy sensitivity fields when UniFi omits an explicit enabled boolean.

### Changed

- Added raw IDS config storage on `ids_config.raw_json` for future diagnostics and widened `ids_config.mode` to 32 characters.
- Added focused IDS normalisation tests covering UDR-style prevention, detection-only, disabled, secondary evidence, legacy payloads, and camelCase field names.

### Validation

- Python syntax validation passed for poller, assessment routers/services, network model, IDS migration, and IDS normalisation tests.
- Pytest execution could not run in this local environment because `pytest` and API dependencies are not installed for the available Python interpreter.

## Unreleased - 2026-05-28 (session 10)

### Fixed

- Fixed threat feed firewall rule approval failing with UniFi `api.err.FirewallRuleIndexExisted`. Generated v1 firewall rules now allocate the next available `rule_index` per ruleset starting at `20000` instead of reusing the same fixed index for every generated rule.
- Added a one-time defensive retry for firewall rule creation if UniFi still reports a rule-index collision after the first allocation, refreshing the live ruleset index list before retrying.

### Validation

- Python syntax validation passed for `collectors/threat_feed_collector.py`, `services/unifi_client.py`.

## Unreleased - 2026-05-28 (session 9)

### Added

- Added a reusable non-blocking success toast for completed frontend actions. The toast auto-dismisses after 3 seconds, can be manually dismissed, uses `aria-live="polite"`, and avoids blocking page navigation.

### Changed

- Settings now shows `Save successful` only after settings are successfully persisted through the API.
- Settings CVE and threat feed `Run Now` actions now show `Refresh successful` only after the refresh API call succeeds.
- Threat Feeds page `Refresh` now shows `Refresh successful` only after the refresh API call succeeds.
- Settings refresh failures now render a visible inline error message instead of failing silently.
- Moved success toast rendering to an app-level provider that portals directly to `document.body`, making overlays visible across all routes and independent of page layout.

### Validation

- Frontend production build passed with `npm run build`.
- Frontend build emitted the existing Vite chunk-size warning; no build failure occurred.

## Unreleased - 2026-05-28 (session 8)

### Fixed

- Fixed 404 on `POST /integration/v1/sites/default/firewall-policies` — the v2 integration API has no write endpoint for firewall policies. Reverted `_apply_change` create path to use v1 `create_firewall_rule` and delete path to use `delete_firewall_rule`. The actual original bug (session 6's motivation) was that `src_firewallgroup_ids` was hardcoded as `[]` in the rule payload; it is now populated with the group ID at call time (`{**rule_payload, "src_firewallgroup_ids": [group_id]}`).
- Changed `rule_index` from `10` to `20000` so auto-generated block rules are appended at the end of the rule list rather than near user-defined rules at the top.
- Removed dead v2-only code added in session 6: `_RULESET_ZONES`, `_zones_for_ruleset()`, `_policy_payload()` from `threat_feed_collector.py`, and `create_firewall_policy()`, `update_firewall_policy()`, `delete_firewall_policy()` from `unifi_client.py`.

### Validation

- Python syntax validation passed for `collectors/threat_feed_collector.py`, `services/unifi_client.py`.

## Unreleased - 2026-05-28 (session 7)

### Fixed

- Fixed opaque `400` errors on firewall group creation by including the UniFi response body in all `httpx.HTTPStatusError` exceptions. Added `_raise_with_body()` helper applied to both `_get()` and `_request()` in `unifi_client.py`, so the exact UniFi rejection reason is now visible in the UI "failed" error field and API logs rather than just the status code and URL.
- Fixed `create_firewall_group()` failing with 400 when a same-named group already exists in UniFi from a prior failed approval attempt. On a 400 response the function now GETs the full group list, finds the orphaned group by name, logs a warning, and returns it so policy creation can proceed. The 400 is still re-raised if no matching group is found, now with the response body attached.

### Validation

- Python syntax validation passed for `services/api/app/services/unifi_client.py`.

## Unreleased - 2026-05-28 (session 6)

### Fixed

- Fixed HTTP 500 on Approve caused by a `UNIQUE(ruleset, chunk_index, action, payload_hash, status)` constraint violation. When a second approval attempt failed, trying to insert `status="failed"` conflicted with an existing failed record from the prior attempt. `_queue_pending_rule` now deletes stale `failed`/`rejected` records for the same key before inserting a new pending entry, preventing the `IntegrityError` that propagated to HTTP 500.
- Migrated threat feed enforcement from the legacy v1 `/rest/firewallrule` endpoint to the v2 `/firewall-policies` endpoint. Added `create_firewall_policy`, `update_firewall_policy`, and `delete_firewall_policy` to `unifi_client.py`. Added `_zones_for_ruleset` (maps ruleset names to UniFi v2 zone pairs) and `_policy_payload` (builds the v2 zone policy payload with address group reference) to `threat_feed_collector.py`. `_apply_change` now uses these for create and delete; update still only refreshes the group members.

### Validation

- Python compile validation passed for `collectors/threat_feed_collector.py`, `services/unifi_client.py`.

## Unreleased - 2026-05-28 (session 5)

### Fixed

- Fixed approve/reject `onSuccess` handler discarding the returned rule's `status` field. When `apply_pending_rule` returns HTTP 200 with `status: "failed"`, the error message from `data.error` is now shown in the error banner and the rule is still removed from the pending list. Previously `setActionError(null)` was called unconditionally, so failures were silently cleared.
- Fixed IDS/IPS false-negative on UniFi Network 10 "Detection Mode: Notify". The `mode` field is coerced to `None` when empty string (falsy), and `sensitivity` is added as a final fallback indicator — UniFi sets `sensitivity` (e.g. `"medium"`) whenever IDS/IPS is configured at any level, even detection-only mode.

### Validation

- Python compile validation passed for `collectors/poller.py`.
- Frontend production build passed with `npm run build`.

## Unreleased - 2026-05-28 (session 4)

### Fixed

- Fixed approve/reject/refresh mutations on the Threat Feeds page silently discarding errors. Added `onError` handlers that display an inline error banner above the Pending Rule Changes table so any HTTP 4xx/500 response is visible rather than swallowed.
- Fixed approve and reject router endpoints only catching `ValueError`; unhandled exceptions now produce an HTTP 500 with the error detail rather than an opaque FastAPI error, ensuring `onError` receives a useful message.
- Fixed "Approving…"/"Rejecting…" button labels and `disabled` state during in-flight mutations so double-clicks are prevented.
- Fixed `colSpan` on the empty-state row in the Pending Rule Changes table (6 → 7) to match the seven-column header.

### Changed

- Added loading labels ("Approving…" / "Rejecting…") and `disabled` state on Approve/Reject buttons while a mutation is in flight.

### Validation

- Python compile validation passed for `routers/threatfeed.py`.
- Frontend production build passed with `npm run build`.

## Unreleased - 2026-05-28 (session 3)

### Fixed

- Fixed IDS/IPS enabled detection incorrectly reporting "not enabled" on UniFi Network 9.x/10.x. The poller now treats a non-null mode value (`"ids"`, `"ips"`, etc.) as evidence that IDS is active, handling firmware that returns a mode field without an explicit `enabled: true`. Added `log.info` of the raw IDS config dict to aid on-device diagnostics.
- Fixed Spamhaus DROP v4 feed parse error ("Extra data: line 2 column 1"). The feed switched to JSONL format (one JSON object per line). The `_fetch_feed` function now falls back to line-by-line JSONL parsing when standard `json.loads` fails, leaving all other JSON feeds unchanged.
- Fixed threat feed enforcement silently recording "applied" status when UniFi did not return a firewall rule ID. Added a missing `rule_id` guard (matching the existing `group_id` guard) that raises `ValueError` so the failure is stored visibly. Added `log.info` of the created group and rule IDs for diagnostics.

### Changed

- Added a Status column to the Pending Rule Changes table showing colour-coded status (`pending`, `applied`, `failed`, `rejected`) and the full error message for failed rules.
- Restricted approve/reject buttons in the pending rules table to rows with `pending` status; resolved rows now show their final status instead.

### Validation

- Python compile validation passed for `collectors/poller.py`, `collectors/threat_feed_collector.py`.
- Frontend production build passed with `npm run build`.

## Unreleased - 2026-05-28 (session 2)

### Added

- Added persistent footer to every page with links to maddogwarner.com and github.com/MaddogWarner.
- Added "UniFi Connection" section to the Settings page for runtime configuration of UniFi host URL, API key, site name, and SSL verification without restarting the stack.

### Changed

- Updated `App.tsx` layout to flex-column with `flex-1` on the main content area so the footer is always anchored to the bottom of the viewport.
- Extended `VALID_SETTINGS` allowlist in the settings router to accept `unifi.host`, `unifi.api_key`, `unifi.site`, and `unifi.verify_ssl`, with validation for non-empty values, URL format, and boolean types.
- Seeded UniFi connection settings from environment variables into `app_settings` on first startup so the Settings page is pre-populated.
- Refactored `unifi_client.py` to replace module-level `_BASE_V1`, `_BASE_V2`, and `_HEADERS` constants with a `_load_config()` async function that reads live values from the database (falling back to env vars) on every call. All 15 public functions updated. UniFi credentials can now be changed via the Settings page and take effect on the next poll cycle without a container restart.

### Validation

- Frontend production build passed with `npm run build`.
- Python compile validation passed for `unifi_client.py`, `routers/settings.py`, and `main.py`.

## Unreleased - 2026-05-28

### Added

- Added Phase 2 CVE monitoring backend support, including settings storage, device inventory, CVE alert, and CVE-to-device link models plus Alembic migration `002_cve_threatfeed_settings`.
- Added CVE collector for NVD modified-feed polling, Ubiquiti security bulletin correlation, UniFi device inventory sync, and device-to-CVE matching.
- Added threat feed ingestion for FireHOL, Spamhaus, and custom HTTP/HTTPS feeds with IP/CIDR validation and SSRF-resistant URL checks.
- Added threat feed UniFi enforcement workflow with two modes: `preview` for manual per-rule approval and `auto` for direct UniFi group/rule creation.
- Added pending threat-feed rule approval records and API endpoints to approve or reject each proposed rule change.
- Added settings, CVE, and threat feed FastAPI routers and Pydantic schemas.
- Added Settings, CVE Alerts, and Threat Feeds frontend pages with navigation entries.
- Added frontend controls for threat feed apply mode, target rulesets, source management, pending approvals, and blocked-entry search.
- Added MCP tools for CVE alerts, CVE device inventory, threat feed status, threat feed entries, and pending threat feed approvals.

### Changed

- Extended the existing function-based UniFi client with device, firewall group, and firewall rule write helpers rather than introducing a new client class.
- Seeded default Phase 2 settings and disabled default threat feed sources at API startup.
- Updated API startup to run CVE and threat feed collectors alongside the existing UniFi poller and syslog collector.
- Renamed the threat feed URL validator to `validate_outbound_url` because it is intentionally reused by the threat feed router.
- Removed unused dead interval-validation code from the one-shot threat feed collector.

### Security

- Defaulted threat feed enforcement to `preview` mode so firewall rule changes require explicit operator approval before being pushed to UniFi.
- Added feed URL validation to reject local, private, link-local, multicast, reserved, and metadata endpoints for custom threat feed downloads.
- Added settings validation for booleans, polling intervals, supported UniFi rulesets, proxy URL format, and threat feed apply mode.

### Validation

- Python compile validation passed for API, Alembic, scanner, and MCP code.
- Frontend production build passed with `npm run build`.
- Frontend build emitted the existing Vite chunk-size warning; no build failure occurred.

## Unreleased - 2026-05-27

### Added

- Added `AGENTS.md` with Codex project instructions aligned to `CLAUDE.md`, including Australian English, healthcare cyber security context, secure coding expectations, and multi-agent collaboration guidance.
- Added Docker Compose stack for PostgreSQL, FastAPI API, React frontend, MCP server, scanner service, and nginx ingress.
- Added nginx reverse proxy configuration for frontend and `/api` routing.
- Added environment template and baseline `.gitignore`.
- Added FastAPI application scaffold with settings, database session handling, Alembic setup, initial migration, SQLAlchemy models, Pydantic schemas, routers, UniFi API client, poller, syslog receiver, policy conflict detection, and security assessment service.
- Added scanner microservice using `nmap` with an enforced RFC1918 target guard.
- Added MCP service exposing dashboard tools for firewall policies, firewall logs, threats, IDS status, VLANs, assessment results, policy conflicts, drift reports, scan triggers, and scan results.
- Added React/Vite dashboard with pages for dashboard overview, firewall, threats, VLANs, assessment, and scanner workflows.
- Added reusable frontend components including navigation, status cards, severity badges, and zone matrix visualisation.
- Added project README with prerequisites, quick start, syslog setup, MCP connection details, scanner guardrails, environment variables, and validation commands.

### Changed

- Updated API Docker image to use a non-editable production install with `pip install --no-cache-dir .`.
- Removed direct host exposure of API port `8000`; API ingress now goes through nginx in the committed Compose stack.
- Updated API Compose dependency on scanner from `service_started` to `service_healthy`.
- Made Vite development API proxy configurable through `VITE_API_URL`, with documentation in `.env.example` and `README.md`.
- Standardised `IdsConfig` reads on the latest `synced_at` value across poller, assessment, and threats code paths.
- Updated poller to remove stale `IdsConfig` rows after upsert so duplicate configuration records do not accumulate.
- Updated `StatusCard` value colour styling so the displayed value follows the selected tone.
- Marked all reviewed findings in `issues.md` as fixed.

### Fixed

- Fixed policy conflict detection so same-action policies with overlapping protocols, including `None` match-all versus a specific protocol, are flagged as duplicates.
- Added scanner `/health` endpoint and Compose healthcheck to avoid early API scan requests failing while the scanner is still starting.
- Fixed MCP firewall log query construction to use URL encoding for query parameters.

### Validation

- Python compile validation passed for API, Alembic, scanner, and MCP code.
- Frontend production build passed with `npm run build`.
- Frontend dev server responded with HTTP `200 OK` on the selected local port.
- Docker Compose syntax could not be validated in this environment because Docker was not installed or available on `PATH`.
- In-app browser visual verification could not be completed because the Browser plugin reported the `iab` browser was unavailable.
