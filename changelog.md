# Changelog

All notable project changes are recorded here.

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
