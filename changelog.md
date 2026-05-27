# Changelog

All notable project changes are recorded here.

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
