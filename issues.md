# Issues

Code review against the architecture in `CLAUDE.md`. Issues rated: **Critical → High → Medium → Minor**.

---

## CRITICAL

### ISS-001 — Policy conflict detection has a logic gap
**File:** [services/api/app/services/policy_engine.py:41](services/api/app/services/policy_engine.py#L41)
**Status:** Fixed

The duplicate-policy check uses `elif first.protocol == second.protocol`. This misses cases where both policies have the same action and zone pair but one protocol is `None` (match-all) and the other is a specific protocol (e.g., `tcp`). Those policies are redundant — the any-protocol rule fully subsumes the tcp-only rule — but won't be flagged.

```python
# current — misses None vs "tcp" overlap
elif first.protocol == second.protocol:

# fix — overlaps already guarantees they match; just flag it
else:
```

---

## HIGH

### ISS-002 — Editable install (`-e`) used in production Docker image
**File:** [services/api/Dockerfile:11](services/api/Dockerfile#L11)
**Status:** Fixed

```dockerfile
RUN pip install --no-cache-dir -e .   # wrong — editable mode
RUN pip install --no-cache-dir .      # correct
```

Editable installs symlink to the source directory. Fine for local dev; wrong for a container where the source tree is the installed package. Has no runtime effect in this image because the source is copied in, but is non-idiomatic and will break if the COPY order changes.

---

### ISS-003 — API port 8000 exposed directly on the host
**File:** [docker-compose.yml:27-28](docker-compose.yml#L27-L28)
**Status:** Fixed

```yaml
api:
  ports:
    - "8000:8000"   # bypasses nginx entirely
```

The API is accessible directly at `http://host:8000`, bypassing nginx. Any future auth middleware or rate-limiting placed in nginx is trivially bypassed. In a home-lab context this is low risk, but it's inconsistent with the architecture (nginx is the intended ingress).

**Fix:** Remove the `ports` entry from `api`. For local debugging, use `127.0.0.1:8000:8000` only when needed and not committed.

---

### ISS-004 — Scanner service has no healthcheck; `api` may attempt connections before scanner is ready
**File:** [docker-compose.yml:45-50](docker-compose.yml#L45-L50)
**Status:** Fixed

`api` depends on `scanner` with `condition: service_started`, which only waits for the container process to start — not for the HTTP server inside it to be accepting connections. An early scan request during startup will get a connection refused from `http://scanner:8002`.

**Fix:** Add a healthcheck to the scanner service:
```yaml
scanner:
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:8002/docs"]
    interval: 5s
    timeout: 5s
    retries: 10
```
And in `api` change `condition: service_started` → `condition: service_healthy`.
`curl` needs to be available in the scanner image — verify or substitute with a Python-based check.

---

## MEDIUM

### ISS-005 — MCP query params built without URL encoding
**File:** [services/mcp/server.py:26-31](services/mcp/server.py#L26-L31)
**Status:** Fixed

`src_ip` and `rule_name` from the tool caller are concatenated directly into the URL query string without encoding. If either contains `&`, `=`, or other reserved characters the server will misparse the query. Unlikely in practice (IPs are well-formatted) but not correct.

```python
# current
params = f"?limit={limit}"
if src_ip:
    params += f"&src_ip={src_ip}"

# fix — use urllib.parse.urlencode
from urllib.parse import urlencode
params = "?" + urlencode({k: v for k, v in {"limit": limit, "src_ip": src_ip, "rule_name": rule_name}.items() if v})
```

---

### ISS-006 — Frontend Vite dev proxy hardcoded to `localhost:8000`
**File:** [services/frontend/vite.config.ts](services/frontend/vite.config.ts)
**Status:** Fixed

The dev server proxy target is `http://localhost:8000`. If the API runs in Docker (as the stack is designed), the API is not on `localhost` from the frontend dev server's perspective. Developers running `npm run dev` against a Dockerised API will get proxy errors.

**Fix:** Either document the workaround (expose api:8000 on localhost during dev, which ISS-003 fix would remove), or make the target configurable via `VITE_API_URL` env var.

---

### ISS-007 — Inconsistent `IdsConfig` fetch ordering across files
**File:** [services/api/app/collectors/poller.py](services/api/app/collectors/poller.py) vs [services/api/app/routers/assessment.py:21](services/api/app/routers/assessment.py#L21) and [services/api/app/routers/threats.py](services/api/app/routers/threats.py)
**Status:** Fixed

`poller.py` fetches IdsConfig ordered by `id.asc()`; `assessment.py` and `threats.py` use `synced_at.desc()`. The result is functionally the same today (there's effectively one row), but the inconsistency signals unclear intent and will silently return the wrong row if multiple rows accumulate.

**Fix:** Standardise on `order_by(IdsConfig.synced_at.desc()).limit(1)` everywhere, and ensure `poller.py` deletes stale rows after upsert rather than inserting duplicates.

---

## MINOR

### ISS-008 — `StatusCard` text colour ignores `tone` on value display
**File:** [services/frontend/src/components/StatusCard.tsx:23](services/frontend/src/components/StatusCard.tsx#L23)
**Status:** Fixed

The value text is hardcoded to `text-slate-950` regardless of the tone prop. When tone is `"bad"` (rose background), the value should render in `text-rose-900` to match the card style. Currently readable but inconsistent with the component's colour system.

---

### ISS-009 — Firewall rule `action` value unverified against UniFi legacy API

**File:** [services/api/app/collectors/threat_feed_collector.py](services/api/app/collectors/threat_feed_collector.py) (`_rule_payloads`)
**Status:** Open

The threat feed rule payload uses `"action": "drop"`. The UniFi legacy `rest/firewallrule` API likely accepts `accept`, `drop`, and `reject`, making `"drop"` correct. However, some firmware versions or legacy controller releases use `"deny"` instead. If the value is wrong, rule creation will silently succeed (201 returned) but the rule will have no effect or be misconfigured.

**Verify:** After deploying to a real UniFi console, enable the threat feed and inspect the created firewall rule in the UniFi dashboard. Confirm the action is applied correctly. If the rule appears with no action or an unexpected value, change `"drop"` to `"deny"` in `_rule_payloads()`.

### ISS-010 — MISP source credentials cannot be edited after creation

**File:** [services/frontend/src/lib/api.ts:375](services/frontend/src/lib/api.ts#L375) (`updateThreatFeedSource`)
**Status:** Open

`updateThreatFeedSource` accepts `Partial<ThreatFeedSource>`, but `ThreatFeedSource` does not include `api_key` or `misp_verify_ssl` (those fields are intentionally absent from the response type to avoid exposing the key). As a result, there is no UI path to rotate a MISP API key or toggle SSL verification after the source is created. The backend `PUT /feeds/{id}` endpoint already handles both fields via `ThreatFeedUpdate`.

**Workaround:** Delete and re-add the MISP source with the new credentials.

**Fix:** Add a separate `ThreatFeedUpdatePayload` type that includes `api_key` and `misp_verify_ssl`, update `updateThreatFeedSource` to accept it, and add an edit form or modal for MISP sources in `ThreatFeeds.tsx`.

---

## DISMISSED (false positives from review tools)

- **Scanner port parameter injection** — `asyncio.create_subprocess_exec` passes args directly to `execve()` without a shell; no injection risk. Pydantic `max_length=256` is sufficient validation.
- **MCP `transport="streamable-http"` string** — Valid FastMCP API; `run()` accepts transport name as a string in mcp SDK v1.0+.
- **`.gitignore` missing service-level patterns** — `node_modules/` and `dist/` patterns match recursively; subdirectory paths are covered. No git repo has been initialised yet so nothing has been committed.
