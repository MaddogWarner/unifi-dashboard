# UniFi Security Dashboard — Codex Implementation Plan (Phase 2)

## Overview

Phase 1 (original 10-step build) is complete. This plan adds two new optional features:

1. **CVE Monitoring** — poll NVD for Ubiquiti CVEs, compare against device firmware, surface HIGH/CRITICAL alerts
2. **Threat Feed Integration** — poll IP blocklists (FireHOL, Spamhaus DROP), push blocked IPs into UniFi as address groups + firewall rules

Both features are disabled by default and toggled from a new Settings page. Both support an optional HTTP proxy for environments without direct internet access.

Implementation note: threat feed enforcement now supports two operator-selected modes:
- `preview` — default. Feed polling creates pending UniFi rule changes that must be individually approved or rejected.
- `auto` — feed polling directly creates, updates, or deletes dashboard-managed UniFi address groups and firewall rules.

---

## Architecture Overview of New Components

```
app_settings (DB key/value) ← Settings page reads/writes
     ↓
cve_collector.py  ← polls NVD JSON feed + community.ui.com
     ↓ writes
device_inventory, cve_alerts, cve_device_links

threat_feed_collector.py ← polls FireHOL/Spamhaus/custom URLs
     ↓ writes                        ↓ calls
threat_feed_entries           UniFi firewallgroup + firewallrule API
     ↑ tracked by
threat_feed_rules (group_id, rule_id per chunk/zone)
     ↑ preview queue
threat_feed_pending_rules
```

---

## Step 1 — Database Models and Alembic Migration

### 1a. New models

Create `services/api/app/models/settings.py`:

```python
from datetime import datetime
from sqlalchemy import String, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(default=func.now(), onupdate=func.now())
```

Create `services/api/app/models/cve.py`:

```python
from datetime import datetime
from decimal import Decimal
from sqlalchemy import String, Text, Numeric, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class DeviceInventory(Base):
    __tablename__ = "device_inventory"

    id: Mapped[int] = mapped_column(primary_key=True)
    unifi_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    name: Mapped[str | None] = mapped_column(String)
    model: Mapped[str | None] = mapped_column(String)
    firmware_version: Mapped[str | None] = mapped_column(String)
    ip_address: Mapped[str | None] = mapped_column(String)
    site: Mapped[str | None] = mapped_column(String)
    raw_json: Mapped[str | None] = mapped_column(Text)
    synced_at: Mapped[datetime | None] = mapped_column()


class CVEAlert(Base):
    __tablename__ = "cve_alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    title: Mapped[str | None] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String, nullable=False)  # HIGH / CRITICAL
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(4, 1))
    published_at: Mapped[datetime | None] = mapped_column()
    source: Mapped[str] = mapped_column(String, default="nvd")
    affected_cpe: Mapped[str | None] = mapped_column(String)
    ubiquiti_bulletin_url: Mapped[str | None] = mapped_column(String)
    acknowledged_at: Mapped[datetime | None] = mapped_column()
    raw_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=func.now())


class CVEDeviceLink(Base):
    __tablename__ = "cve_device_links"
    __table_args__ = (UniqueConstraint("cve_id", "device_id"),)

    cve_id: Mapped[str] = mapped_column(ForeignKey("cve_alerts.cve_id", ondelete="CASCADE"), primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device_inventory.id", ondelete="CASCADE"), primary_key=True)
```

Create `services/api/app/models/threatfeed.py`:

```python
from datetime import datetime
from sqlalchemy import String, Text, Boolean, Integer, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class ThreatFeedSource(Base):
    __tablename__ = "threat_feed_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_polled_at: Mapped[datetime | None] = mapped_column()
    last_entry_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=func.now())


class ThreatFeedEntry(Base):
    __tablename__ = "threat_feed_entries"
    __table_args__ = (UniqueConstraint("cidr", "feed_source_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String, nullable=False)
    feed_source_id: Mapped[int] = mapped_column(ForeignKey("threat_feed_sources.id", ondelete="CASCADE"))
    added_at: Mapped[datetime] = mapped_column(default=func.now())


class ThreatFeedRule(Base):
    __tablename__ = "threat_feed_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    ruleset: Mapped[str] = mapped_column(String, nullable=False)
    group_unifi_id: Mapped[str] = mapped_column(String, nullable=False)
    rule_unifi_id: Mapped[str | None] = mapped_column(String)
    chunk_index: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(default=func.now())


class ThreatFeedPendingRule(Base):
    """Queued UniFi rule change used when threat_feed.apply_mode is preview."""
    __tablename__ = "threat_feed_pending_rules"
```

### 1b. Alembic migration

Create `services/api/alembic/versions/002_cve_threatfeed_settings.py`.

The migration must create all 7 new tables in dependency order:
1. `app_settings`
2. `device_inventory`
3. `cve_alerts`
4. `cve_device_links`
5. `threat_feed_sources`
6. `threat_feed_entries`
7. `threat_feed_rules`

Use `op.create_table()` for each. Match column types exactly from the models above. Set the `down_revision` to the ID of the existing `001` migration (look up the actual value in `alembic/versions/`).

---

## Step 2 — UniFi Client Extensions

In `services/api/app/services/unifi_client.py`, add these methods to the `UniFiClient` class. All use the v1 (`_v1`) base URL and follow the same pattern as existing methods (headers, retry logic, response extraction).

```python
async def get_devices(self) -> list[dict]:
    """GET /stat/device — returns all managed devices with firmware versions."""
    resp = await self._client.get(f"{self._v1}stat/device")
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", data) if isinstance(data, dict) else data

async def get_firewall_groups(self) -> list[dict]:
    resp = await self._client.get(f"{self._v1}rest/firewallgroup")
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", data) if isinstance(data, dict) else data

async def create_firewall_group(self, payload: dict) -> dict:
    resp = await self._client.post(f"{self._v1}rest/firewallgroup", json=payload)
    resp.raise_for_status()
    data = resp.json()
    items = data.get("data", data) if isinstance(data, dict) else data
    return items[0] if isinstance(items, list) else items

async def update_firewall_group(self, group_id: str, payload: dict) -> dict:
    resp = await self._client.put(f"{self._v1}rest/firewallgroup/{group_id}", json=payload)
    resp.raise_for_status()
    data = resp.json()
    items = data.get("data", data) if isinstance(data, dict) else data
    return items[0] if isinstance(items, list) else items

async def delete_firewall_group(self, group_id: str) -> None:
    resp = await self._client.delete(f"{self._v1}rest/firewallgroup/{group_id}")
    resp.raise_for_status()

async def create_firewall_rule(self, payload: dict) -> dict:
    resp = await self._client.post(f"{self._v1}rest/firewallrule", json=payload)
    resp.raise_for_status()
    data = resp.json()
    items = data.get("data", data) if isinstance(data, dict) else data
    return items[0] if isinstance(items, list) else items

async def update_firewall_rule(self, rule_id: str, payload: dict) -> dict:
    resp = await self._client.put(f"{self._v1}rest/firewallrule/{rule_id}", json=payload)
    resp.raise_for_status()
    data = resp.json()
    items = data.get("data", data) if isinstance(data, dict) else data
    return items[0] if isinstance(items, list) else items

async def delete_firewall_rule(self, rule_id: str) -> None:
    resp = await self._client.delete(f"{self._v1}rest/firewallrule/{rule_id}")
    resp.raise_for_status()
```

Note: the existing `UniFiClient.__init__` already stores `self._v1` as the v1 base URL. Follow whatever attribute naming convention the existing code uses.

---

## Step 3 — CVE Collector

Create `services/api/app/collectors/cve_collector.py`.

### Settings helpers

```python
async def _get_setting(session, key: str, default: str = "") -> str:
    row = await session.get(AppSetting, key)
    return row.value if row else default
```

### Main loop structure

```python
async def run_cve_collector():
    while True:
        try:
            async with async_session() as session:
                enabled = await _get_setting(session, "cve_monitoring.enabled", "false")
                if enabled.lower() != "true":
                    await asyncio.sleep(60)
                    continue
                interval_hours = int(await _get_setting(session, "cve_monitoring.poll_interval_hours", "24"))
                proxy_url = await _get_setting(session, "http_proxy.url", "")
                proxy_enabled = (await _get_setting(session, "http_proxy.enabled", "false")).lower() == "true"

            await _run_nvd_poll(proxy_url if proxy_enabled else None)
            await _run_bulletin_scrape(proxy_url if proxy_enabled else None)
            await _update_device_inventory(proxy_url if proxy_enabled else None)
            await _match_cves_to_devices()
        except Exception:
            logging.exception("CVE collector error")
        await asyncio.sleep(interval_hours * 3600)
```

### NVD feed download (`_run_nvd_poll`)

1. Use `httpx.AsyncClient` with proxy if provided
2. `GET https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz`
3. Decompress with `gzip.decompress(response.content)`
4. Parse JSON: `data = json.loads(decompressed)`
5. Iterate `data["vulnerabilities"]`:
   ```python
   for item in data["vulnerabilities"]:
       cve = item["cve"]
       cve_id = cve["id"]
       
       # Extract CVSS score — try v3.1 first, then v3.0, then v2
       score = None
       severity = None
       metrics = cve.get("metrics", {})
       for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
           if key in metrics and metrics[key]:
               score = metrics[key][0]["cvssData"]["baseScore"]
               severity = metrics[key][0]["cvssData"]["baseSeverity"]
               break
       
       if score is None or score < 7.0:
           continue
       
       # Check if any CPE criterion references vendor "ui"
       has_ubiquiti = False
       for config in cve.get("configurations", []):
           for node in config.get("nodes", []):
               for match in node.get("cpeMatch", []):
                   if ":ui:" in match.get("criteria", ""):
                       has_ubiquiti = True
                       break
       if not has_ubiquiti:
           continue
       
       # Build title from first English description
       title = next(
           (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
           cve_id
       )[:200]
       description = title  # use same for description (full text truncated)
       
       published = cve.get("published")
       affected_cpe = next(
           (
               node["cpeMatch"][0]["criteria"]
               for config in cve.get("configurations", [])
               for node in config.get("nodes", [])
               if node.get("cpeMatch")
           ),
           None
       )
       
       # Upsert into cve_alerts (insert or ignore on conflict)
       ...
   ```
6. Use `INSERT ... ON CONFLICT (cve_id) DO NOTHING` to avoid overwriting acknowledged records

### Ubiquiti bulletin scrape (`_run_bulletin_scrape`)

1. `GET https://community.ui.com/releases` — fetch HTML
2. Regex: `re.findall(r'href="(/releases/Security-Advisory-Bulletin[^"]+)"', html)`
3. For each URL found, `GET https://community.ui.com{path}`
4. Extract CVE IDs from page text: `re.findall(r'CVE-\d{4}-\d+', page_html)`
5. For each CVE ID:
   - If already in `cve_alerts`, update `source='ubiquiti'` and `ubiquiti_bulletin_url=url` where currently `source='nvd'`
   - If not in DB (NVD didn't capture it), insert with source='ubiquiti', severity='HIGH' (default, since no CVSS), cvss_score=None

### Device inventory update (`_update_device_inventory`)

1. Call `unifi_client.get_devices()`
2. For each device: upsert `device_inventory` on `unifi_id`
   - Extract `_id` or `mac` as `unifi_id`
   - Extract `model`, `version` as `firmware_version`, `name`, `ip` as `ip_address`

### CVE → device matching (`_match_cves_to_devices`)

```python
async with async_session() as session:
    devices = (await session.execute(select(DeviceInventory))).scalars().all()
    cves = (await session.execute(select(CVEAlert))).scalars().all()
    
    for cve in cves:
        if not cve.affected_cpe:
            continue
        cpe_lower = cve.affected_cpe.lower()
        for device in devices:
            model_lower = (device.model or "").lower()
            version = device.firmware_version or ""
            # Match if model name appears in CPE string
            if model_lower and model_lower in cpe_lower:
                # Insert link if not exists
                await session.execute(
                    insert(CVEDeviceLink)
                    .values(cve_id=cve.cve_id, device_id=device.id)
                    .on_conflict_do_nothing()
                )
    await session.commit()
```

---

## Step 4 — Threat Feed Collector

Create `services/api/app/collectors/threat_feed_collector.py`.

### Main loop structure

```python
async def run_threat_feed_collector():
    while True:
        try:
            async with async_session() as session:
                enabled = await _get_setting(session, "threat_feed.enabled", "false")
                interval_hours = int(await _get_setting(session, "threat_feed.poll_interval_hours", "24"))
                proxy_url = await _get_setting(session, "http_proxy.url", "")
                proxy_enabled = (await _get_setting(session, "http_proxy.enabled", "false")).lower() == "true"
                zones_json = await _get_setting(session, "threat_feed.zones", '["WAN_IN", "WAN_LOCAL"]')
                zones = json.loads(zones_json)
            
            if enabled.lower() != "true":
                # If disabled, clean up any existing UniFi rules
                await _cleanup_unifi_rules()
                await asyncio.sleep(60)
                continue
            
            proxy = proxy_url if proxy_enabled else None
            await _poll_all_feeds(proxy)
            await _apply_to_unifi(zones)
        except Exception:
            logging.exception("Threat feed collector error")
        await asyncio.sleep(interval_hours * 3600)
```

### Feed polling (`_poll_all_feeds`)

```python
async def _poll_all_feeds(proxy: str | None):
    async with async_session() as session:
        sources = (
            await session.execute(select(ThreatFeedSource).where(ThreatFeedSource.enabled == True))
        ).scalars().all()
    
    for source in sources:
        try:
            entries = await _fetch_feed(source.url, proxy)
            async with async_session() as session:
                # Delete old entries for this source
                await session.execute(
                    delete(ThreatFeedEntry).where(ThreatFeedEntry.feed_source_id == source.id)
                )
                # Insert new entries
                for cidr in entries:
                    session.add(ThreatFeedEntry(cidr=cidr, feed_source_id=source.id))
                # Update source metadata
                src = await session.get(ThreatFeedSource, source.id)
                src.last_polled_at = datetime.now(timezone.utc)
                src.last_entry_count = len(entries)
                src.last_error = None
                await session.commit()
        except Exception as exc:
            async with async_session() as session:
                src = await session.get(ThreatFeedSource, source.id)
                src.last_error = str(exc)
                src.last_polled_at = datetime.now(timezone.utc)
                await session.commit()
```

### Feed format parsing (`_fetch_feed`)

Handle two formats:
- **Plain text / netset** (FireHOL): one IP or CIDR per line; skip lines starting with `#` or empty lines
- **Spamhaus JSON**: `[{"cidr": "x.x.x.x/nn", ...}, ...]` — extract `cidr` field from each item

```python
async def _fetch_feed(url: str, proxy: str | None) -> list[str]:
    proxies = {"all://": proxy} if proxy else None
    async with httpx.AsyncClient(proxies=proxies, timeout=60) as client:
        resp = await client.get(url)
        resp.raise_for_status()
    
    entries = []
    content_type = resp.headers.get("content-type", "")
    
    if "json" in content_type or url.endswith(".json"):
        data = resp.json()
        if isinstance(data, list):
            for item in data:
                cidr = item.get("cidr") or item.get("ip")
                if cidr:
                    entries.append(cidr.strip())
    else:
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line)
    
    # Validate each entry is a valid IP or CIDR
    valid = []
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
            valid.append(entry)
        except ValueError:
            pass
    return valid
```

### Apply to UniFi (`_apply_to_unifi`)

```python
CHUNK_SIZE = 500

async def _apply_to_unifi(zones: list[str]):
    # Collect all active entries
    async with async_session() as session:
        rows = (await session.execute(select(ThreatFeedEntry))).scalars().all()
    all_ips = list({r.cidr for r in rows})  # deduplicate
    
    chunks = [all_ips[i:i+CHUNK_SIZE] for i in range(0, len(all_ips), CHUNK_SIZE)]
    if not chunks:
        chunks = [[]]  # ensure cleanup still runs
    
    async with async_session() as session:
        existing_rules = (await session.execute(select(ThreatFeedRule))).scalars().all()
    
    existing_by_key = {(r.ruleset, r.chunk_index): r for r in existing_rules}
    needed_keys = {(zone, idx) for zone in zones for idx in range(len(chunks))}
    
    for (ruleset, idx), rule in existing_by_key.items():
        if (ruleset, idx) not in needed_keys:
            # Delete stale rule + group from UniFi and DB
            try:
                if rule.rule_unifi_id:
                    await unifi_client.delete_firewall_rule(rule.rule_unifi_id)
                await unifi_client.delete_firewall_group(rule.group_unifi_id)
            except Exception:
                pass
            async with async_session() as session:
                await session.execute(delete(ThreatFeedRule).where(ThreatFeedRule.id == rule.id))
                await session.commit()
    
    for zone in zones:
        for idx, chunk in enumerate(chunks):
            key = (zone, idx)
            group_name = f"ThreatFeed-{zone}-{idx}"
            rule_name = f"Block-ThreatFeed-{zone}-{idx}"
            
            group_payload = {
                "name": group_name,
                "group_type": "address-group",
                "group_members": chunk,
            }
            rule_payload = {
                "name": rule_name,
                "action": "deny",
                "enabled": True,
                "ruleset": zone,
                "rule_index": 10,
                "src_firewallgroup_ids": [],  # filled after group creation
                "dst_address": "",
                "src_address": "",
                "protocol": "all",
                "logging": True,
            }
            
            if key in existing_by_key:
                rule_row = existing_by_key[key]
                await unifi_client.update_firewall_group(
                    rule_row.group_unifi_id, group_payload
                )
            else:
                group = await unifi_client.create_firewall_group(group_payload)
                group_id = group.get("_id") or group.get("id")
                rule_payload["src_firewallgroup_ids"] = [group_id]
                fw_rule = await unifi_client.create_firewall_rule(rule_payload)
                rule_id = fw_rule.get("_id") or fw_rule.get("id")
                async with async_session() as session:
                    session.add(ThreatFeedRule(
                        ruleset=zone,
                        group_unifi_id=group_id,
                        rule_unifi_id=rule_id,
                        chunk_index=idx,
                    ))
                    await session.commit()


async def _cleanup_unifi_rules():
    """Called when threat feed is disabled. Deletes all created groups/rules."""
    async with async_session() as session:
        rules = (await session.execute(select(ThreatFeedRule))).scalars().all()
    for rule in rules:
        try:
            if rule.rule_unifi_id:
                await unifi_client.delete_firewall_rule(rule.rule_unifi_id)
            await unifi_client.delete_firewall_group(rule.group_unifi_id)
        except Exception:
            pass
    async with async_session() as session:
        await session.execute(delete(ThreatFeedRule))
        await session.execute(delete(ThreatFeedEntry))
        await session.commit()
```

Note: `unifi_client` is a module-level singleton. Import the same instance used by `poller.py`.

---

## Step 5 — FastAPI Routers

### `services/api/app/routers/settings.py`

```python
router = APIRouter()

@router.get("/", response_model=dict[str, str])
async def get_settings(db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(AppSetting))).scalars().all()
    return {r.key: r.value for r in rows}

@router.put("/", response_model=dict[str, str])
async def update_settings(body: SettingsUpdate, db: AsyncSession = Depends(get_db)):
    # Validate minimum threat feed interval
    if "threat_feed.poll_interval_hours" in body.settings:
        if int(body.settings["threat_feed.poll_interval_hours"]) < 1:
            raise HTTPException(400, "threat_feed.poll_interval_hours minimum is 1")
    for key, value in body.settings.items():
        row = await db.get(AppSetting, key)
        if row:
            row.value = value
        else:
            db.add(AppSetting(key=key, value=value))
    await db.commit()
    rows = (await db.execute(select(AppSetting))).scalars().all()
    return {r.key: r.value for r in rows}
```

### `services/api/app/routers/cve.py`

```python
router = APIRouter()

@router.get("/alerts", response_model=CVEListResponse)
async def get_cve_alerts(
    severity: str | None = None,  # HIGH / CRITICAL / None = all
    acknowledged: bool | None = False,  # False = hide acknowledged
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    q = select(CVEAlert)
    if severity:
        q = q.where(CVEAlert.severity == severity.upper())
    if acknowledged is False:
        q = q.where(CVEAlert.acknowledged_at == None)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    items = (await db.execute(q.order_by(CVEAlert.cvss_score.desc()).offset(skip).limit(limit))).scalars().all()
    # Enrich with device names
    result = []
    for item in items:
        links = (await db.execute(
            select(DeviceInventory.name).join(CVEDeviceLink, CVEDeviceLink.device_id == DeviceInventory.id)
            .where(CVEDeviceLink.cve_id == item.cve_id)
        )).scalars().all()
        result.append(CVEAlertSchema.model_validate({**item.__dict__, "affected_devices": [n for n in links if n]}))
    return CVEListResponse(total=total, items=result)

@router.post("/alerts/{cve_id}/acknowledge")
async def acknowledge_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    alert = await db.get(CVEAlert, cve_id)  # note: primary key is `id` (int), look up by cve_id field
    if not alert:
        raise HTTPException(404)
    alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    return {"ok": True}

@router.get("/devices", response_model=list[DeviceInventorySchema])
async def get_devices(db: AsyncSession = Depends(get_db)):
    devices = (await db.execute(select(DeviceInventory))).scalars().all()
    result = []
    for d in devices:
        cve_ids = (await db.execute(
            select(CVEDeviceLink.cve_id).where(CVEDeviceLink.device_id == d.id)
        )).scalars().all()
        result.append(DeviceInventorySchema.model_validate({**d.__dict__, "active_cves": list(cve_ids)}))
    return result

@router.post("/refresh")
async def refresh_cve():
    asyncio.create_task(run_cve_collector_once())  # fire-and-forget single run
    return {"ok": True, "message": "CVE refresh triggered"}
```

### `services/api/app/routers/threatfeed.py`

```python
router = APIRouter()

@router.get("/feeds", response_model=list[ThreatFeedSourceSchema])
async def list_feeds(db: AsyncSession = Depends(get_db)):
    return (await db.execute(select(ThreatFeedSource).order_by(ThreatFeedSource.id))).scalars().all()

@router.post("/feeds", response_model=ThreatFeedSourceSchema, status_code=201)
async def add_feed(body: ThreatFeedCreate, db: AsyncSession = Depends(get_db)):
    feed = ThreatFeedSource(name=body.name, url=body.url)
    db.add(feed)
    await db.commit()
    await db.refresh(feed)
    return feed

@router.put("/feeds/{feed_id}", response_model=ThreatFeedSourceSchema)
async def update_feed(feed_id: int, body: ThreatFeedUpdate, db: AsyncSession = Depends(get_db)):
    feed = await db.get(ThreatFeedSource, feed_id)
    if not feed:
        raise HTTPException(404)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(feed, field, value)
    await db.commit()
    await db.refresh(feed)
    return feed

@router.delete("/feeds/{feed_id}", status_code=204)
async def delete_feed(feed_id: int, db: AsyncSession = Depends(get_db)):
    feed = await db.get(ThreatFeedSource, feed_id)
    if not feed:
        raise HTTPException(404)
    await db.delete(feed)
    await db.commit()

@router.get("/status", response_model=ThreatFeedStatus)
async def get_status(db: AsyncSession = Depends(get_db)):
    enabled_setting = await db.get(AppSetting, "threat_feed.enabled")
    enabled = enabled_setting.value.lower() == "true" if enabled_setting else False
    total = (await db.execute(select(func.count(ThreatFeedEntry.id)))).scalar() or 0
    last = (await db.execute(
        select(func.max(ThreatFeedSource.last_polled_at))
    )).scalar()
    rules = (await db.execute(select(ThreatFeedRule))).scalars().all()
    zone_summary = {}
    for r in rules:
        zone_summary.setdefault(r.ruleset, {"group_count": 0, "rule_count": 0})
        zone_summary[r.ruleset]["group_count"] += 1
        if r.rule_unifi_id:
            zone_summary[r.ruleset]["rule_count"] += 1
    return ThreatFeedStatus(
        enabled=enabled,
        last_updated=last,
        total_entries=total,
        zone_rules=[{"ruleset": k, **v} for k, v in zone_summary.items()],
    )

@router.get("/entries", response_model=dict)
async def list_entries(
    feed_source_id: int | None = None,
    cidr: str | None = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    q = (
        select(ThreatFeedEntry, ThreatFeedSource.name.label("feed_name"))
        .join(ThreatFeedSource, ThreatFeedEntry.feed_source_id == ThreatFeedSource.id)
    )
    if feed_source_id:
        q = q.where(ThreatFeedEntry.feed_source_id == feed_source_id)
    if cidr:
        q = q.where(ThreatFeedEntry.cidr.ilike(f"%{cidr}%"))
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows = (await db.execute(q.offset(skip).limit(limit))).all()
    items = [
        {"id": e.id, "cidr": e.cidr, "feed_source_name": name, "added_at": e.added_at}
        for e, name in rows
    ]
    return {"total": total, "items": items}

@router.post("/refresh")
async def refresh_feeds():
    asyncio.create_task(run_threat_feed_collector_once())
    return {"ok": True, "message": "Threat feed refresh triggered"}
```

---

## Step 6 — Pydantic Schemas

Create `services/api/app/schemas/settings.py`:
```python
class SettingsUpdate(BaseModel):
    settings: dict[str, str]
```

Create `services/api/app/schemas/cve.py`:
```python
class CVEAlertSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cve_id: str
    title: str | None
    description: str | None
    severity: str
    cvss_score: float | None
    published_at: datetime | None
    source: str
    ubiquiti_bulletin_url: str | None
    acknowledged_at: datetime | None
    affected_devices: list[str]
    created_at: datetime

class CVEListResponse(BaseModel):
    total: int
    items: list[CVEAlertSchema]

class DeviceInventorySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str | None
    model: str | None
    firmware_version: str | None
    ip_address: str | None
    synced_at: datetime | None
    active_cves: list[str]
```

Create `services/api/app/schemas/threatfeed.py`:
```python
class ThreatFeedSourceSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    url: str
    enabled: bool
    last_polled_at: datetime | None
    last_entry_count: int
    last_error: str | None
    created_at: datetime

class ThreatFeedCreate(BaseModel):
    name: str
    url: str

class ThreatFeedUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    enabled: bool | None = None

class ThreatFeedStatus(BaseModel):
    enabled: bool
    last_updated: datetime | None
    total_entries: int
    zone_rules: list[dict]

class ThreatFeedEntrySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cidr: str
    feed_source_name: str
    added_at: datetime
```

---

## Step 7 — Update `main.py`

1. Add model imports (so Alembic and create_all see the new tables):
   ```python
   from app.models import firewall, network, scan, threat, settings as settings_model, cve as cve_model, threatfeed as threatfeed_model  # noqa: F401
   ```

2. Import new routers:
   ```python
   from app.routers import settings as settings_router, cve as cve_router, threatfeed as threatfeed_router
   ```

3. Import new collectors:
   ```python
   from app.collectors.cve_collector import run_cve_collector
   from app.collectors.threat_feed_collector import run_threat_feed_collector
   ```

4. In lifespan, after `create_all`, seed defaults and default feed sources:
   ```python
   SETTING_DEFAULTS = {
       "cve_monitoring.enabled": "false",
       "cve_monitoring.poll_interval_hours": "24",
       "threat_feed.enabled": "false",
       "threat_feed.poll_interval_hours": "24",
       "threat_feed.zones": '["WAN_IN", "WAN_LOCAL"]',
       "threat_feed.apply_mode": "preview",
       "http_proxy.enabled": "false",
       "http_proxy.url": "",
   }
   DEFAULT_FEEDS = [
       {"name": "FireHOL Level 1", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"},
       {"name": "Spamhaus DROP", "url": "https://www.spamhaus.org/drop/drop_v4.json"},
   ]
   
   async with async_session() as session:
       for key, value in SETTING_DEFAULTS.items():
           if not await session.get(AppSetting, key):
               session.add(AppSetting(key=key, value=value))
       existing_urls = {r.url for r in (await session.execute(select(ThreatFeedSource))).scalars()}
       for feed in DEFAULT_FEEDS:
           if feed["url"] not in existing_urls:
               session.add(ThreatFeedSource(**feed, enabled=False))
       await session.commit()
   ```

5. Add background tasks:
   ```python
   tasks = [
       asyncio.create_task(run_poll_loop()),
       asyncio.create_task(start_syslog_server()),
       asyncio.create_task(run_cve_collector()),
       asyncio.create_task(run_threat_feed_collector()),
   ]
   ```

6. Register routers:
   ```python
   app.include_router(settings_router.router, prefix="/api/v1/settings", tags=["settings"])
   app.include_router(cve_router.router, prefix="/api/v1/cve", tags=["cve"])
   app.include_router(threatfeed_router.router, prefix="/api/v1/threatfeed", tags=["threatfeed"])
   ```

---

## Step 8 — Frontend: Settings Page

Create `services/frontend/src/pages/Settings.tsx`.

Use `@tanstack/react-query` to fetch settings: `useQuery({ queryKey: ["settings"], queryFn: getSettings })`.

Use `useMutation` with `updateSettings` and `queryClient.invalidateQueries(["settings"])` on success.

Layout (Tailwind, consistent with existing pages):

```
<h1>Settings</h1>

<section> General — Proxy
  <label>Enable HTTP Proxy <input type="checkbox" checked={settings["http_proxy.enabled"] === "true"} /></label>
  <label>Proxy URL <input type="text" value={settings["http_proxy.url"]} /></label>
  <p className="text-sm text-slate-500">Used for CVE monitoring and threat feed downloads when the container host lacks direct internet access.</p>
</section>

<section> CVE Monitoring
  <label>Enable CVE Monitoring <input type="checkbox" /></label>
  <label>Poll Interval
    <select> <option value="6">Every 6 hours</option> <option value="12">Every 12 hours</option> <option value="24">Every 24 hours</option> </select>
  </label>
  <button onClick={refreshCVE}>Run Now</button>
  <span>Last checked: {cve devices last synced_at}</span>
</section>

<section> Threat Feed
  <label>Enable Threat Feed <input type="checkbox" /></label>
  <label>Poll Interval
    <select> <option value="1">Every hour</option> <option value="4">Every 4 hours</option> <option value="8">Every 8 hours</option> <option value="24">Every 24 hours</option> </select>
  </label>
  <fieldset> Target Rulesets (multi-select checkboxes)
    WAN Inbound (WAN_IN)
    WAN Local (WAN_LOCAL)
    LAN Inbound (LAN_IN)
    LAN Outbound (LAN_OUT)
    LAN Local (LAN_LOCAL)
    Guest Inbound (GUEST_IN)
  </fieldset>
  <button onClick={refreshThreatFeed}>Run Now</button>
</section>

<button className="btn-primary" onClick={saveSettings}>Save Settings</button>
```

The zone checkboxes store the selected raw ruleset names in `settings["threat_feed.zones"]` as a JSON array string.

---

## Step 9 — Frontend: CVE Alerts Page

Create `services/frontend/src/pages/CVEAlerts.tsx`.

Data fetching:
- `useQuery(["cve-devices"], getCVEDevices)` — device inventory
- `useQuery(["cve-alerts", filters], () => getCVEAlerts(filters))` — CVE list

Layout:

```
<h1>CVE Alerts</h1>

<div className="grid grid-cols-2 gap-4">
  <StatusCard title="Critical CVEs" value={criticalCount} tone="bad" />
  <StatusCard title="High CVEs" value={highCount} tone="warn" />
</div>

<h2>Device Inventory</h2>
<table>
  <thead>Model | Firmware | IP | Open CVEs</thead>
  <tbody>
    {devices.map(d => (
      <tr onClick={() => setDeviceFilter(d.id)} className={selectedDevice === d.id ? "bg-slate-100" : ""}>
        <td>{d.name || d.model}</td>
        <td>{d.model}</td>
        <td>{d.firmware_version}</td>
        <td>{d.ip_address}</td>
        <td>
          {d.active_cves.length > 0 
            ? <span className="text-rose-600 font-semibold">{d.active_cves.length}</span>
            : <span className="text-emerald-600">Clean</span>
          }
        </td>
      </tr>
    ))}
  </tbody>
</table>

<h2>CVE Alerts</h2>
<div className="flex gap-2">  {/* filter bar */}
  <select onChange={setSeverityFilter}><option>All</option><option>CRITICAL</option><option>HIGH</option></select>
  <label><input type="checkbox" checked={hideAcknowledged} onChange={...} /> Hide Acknowledged</label>
</div>
<table>
  <thead>CVE ID | Severity | CVSS | Title | Published | Affected Devices | Source | Action</thead>
  <tbody>
    {alerts.map(a => (
      <tr>
        <td><a href={`https://nvd.nist.gov/vuln/detail/${a.cve_id}`} target="_blank">{a.cve_id}</a></td>
        <td><SeverityBadge severity={a.severity} /></td>
        <td>{a.cvss_score?.toFixed(1)}</td>
        <td>{a.title}</td>
        <td>{formatDate(a.published_at)}</td>
        <td>{a.affected_devices.join(", ")}</td>
        <td>{a.source === "ubiquiti" ? "Ubiquiti" : "NVD"}</td>
        <td>
          {!a.acknowledged_at
            ? <button onClick={() => acknowledgeCVE(a.id)}>Acknowledge</button>
            : <span className="text-slate-400">Acknowledged</span>
          }
        </td>
      </tr>
    ))}
  </tbody>
</table>
```

Reuse the existing `SeverityBadge` component. Map severity to colour: CRITICAL → rose, HIGH → amber.

---

## Step 10 — Frontend: Threat Feeds Page

Create `services/frontend/src/pages/ThreatFeeds.tsx`.

Data fetching:
- `useQuery(["threatfeed-status"], getThreatFeedStatus)` — refetch every 30s
- `useQuery(["threatfeed-feeds"], getThreatFeedSources)`
- `useQuery(["threatfeed-entries", cidrSearch], () => getThreatFeedEntries({ cidr: cidrSearch }))` — lazy load

Layout:

```
<h1>Threat Feeds</h1>

{/* Status bar */}
<div className="flex items-center gap-4 p-4 rounded-lg bg-slate-50">
  <span className={status.enabled ? "text-emerald-600" : "text-slate-400"}>
    {status.enabled ? "Active" : "Disabled"}
  </span>
  <span>Last updated: {formatDate(status.last_updated)}</span>
  <span>{status.total_entries.toLocaleString()} IPs blocked</span>
  <span>Zones: {status.zone_rules.map(z => z.ruleset).join(", ")}</span>
</div>

{/* Feed management */}
<h2>Feed Sources</h2>
<table>
  <thead>Name | URL | Enabled | Last Polled | Entries | Status | Actions</thead>
  <tbody>
    {feeds.map(feed => (
      <tr>
        <td>{feed.name}</td>
        <td className="font-mono text-sm truncate max-w-xs">{feed.url}</td>
        <td>
          <input type="checkbox" checked={feed.enabled}
            onChange={() => updateFeed(feed.id, { enabled: !feed.enabled })} />
        </td>
        <td>{formatDate(feed.last_polled_at)}</td>
        <td>{feed.last_entry_count.toLocaleString()}</td>
        <td>
          {feed.last_error
            ? <span className="text-rose-600 text-xs">{feed.last_error}</span>
            : <span className="text-emerald-600 text-xs">OK</span>
          }
        </td>
        <td><button onClick={() => deleteFeed(feed.id)}>Remove</button></td>
      </tr>
    ))}
  </tbody>
</table>

{/* Add feed form */}
<div className="flex gap-2">
  <input placeholder="Name" value={newName} onChange={...} />
  <input placeholder="URL" value={newUrl} onChange={...} />
  <div className="flex gap-1">  {/* quick-add buttons */}
    <button onClick={() => { setNewName("FireHOL Level 1"); setNewUrl("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset") }}>+ FireHOL L1</button>
    <button onClick={() => { setNewName("Spamhaus DROP"); setNewUrl("https://www.spamhaus.org/drop/drop_v4.json") }}>+ Spamhaus</button>
  </div>
  <button onClick={addFeed}>Add</button>
</div>

{/* Blocked entries */}
<h2>Blocked IPs</h2>
<input placeholder="Search CIDR..." value={cidrSearch} onChange={...} />
<table>
  <thead>CIDR | Feed Source | Added</thead>
  <tbody>
    {entries.items.map(e => (
      <tr><td className="font-mono">{e.cidr}</td><td>{e.feed_source_name}</td><td>{formatDate(e.added_at)}</td></tr>
    ))}
  </tbody>
</table>
<div>{/* pagination controls */}</div>
```

---

## Step 11 — Update NavBar, App.tsx, api.ts

### `NavBar.tsx`

Add three new items to the navigation list:

```tsx
// Near bottom of nav, before or after existing items
{ to: "/cve", label: "CVE Alerts", icon: <ShieldAlert size={18} />, badge: unacknowledgedCritical }
{ to: "/threatfeeds", label: "Threat Feeds", icon: <ShieldBan size={18} />, badge: feedError ? "!" : undefined }
// At very bottom
{ to: "/settings", label: "Settings", icon: <Settings size={18} /> }
```

The badge counts require fetching `getCVEAlerts({ acknowledged: false, severity: "CRITICAL" })` and `getThreatFeedSources()` in NavBar (or pass as props from App.tsx).

`lucide-react` already provides `ShieldAlert`, `ShieldBan`, and `Settings` icons.

### `App.tsx`

```tsx
import Settings from "./pages/Settings"
import CVEAlerts from "./pages/CVEAlerts"
import ThreatFeeds from "./pages/ThreatFeeds"

// Add to Routes:
<Route path="/settings" element={<Settings />} />
<Route path="/cve" element={<CVEAlerts />} />
<Route path="/threatfeeds" element={<ThreatFeeds />} />
```

### `src/lib/api.ts`

Add TypeScript types and API functions. Follow the existing pattern in the file:

```typescript
// --- Types ---

export interface CVEAlert {
  id: number
  cve_id: string
  title: string | null
  description: string | null
  severity: string
  cvss_score: number | null
  published_at: string | null
  source: string
  ubiquiti_bulletin_url: string | null
  acknowledged_at: string | null
  affected_devices: string[]
  created_at: string
}

export interface CVEListResponse {
  total: number
  items: CVEAlert[]
}

export interface DeviceInventory {
  id: number
  name: string | null
  model: string | null
  firmware_version: string | null
  ip_address: string | null
  synced_at: string | null
  active_cves: string[]
}

export interface ThreatFeedSource {
  id: number
  name: string
  url: string
  enabled: boolean
  last_polled_at: string | null
  last_entry_count: number
  last_error: string | null
  created_at: string
}

export interface ThreatFeedStatus {
  enabled: boolean
  last_updated: string | null
  total_entries: number
  zone_rules: Array<{ ruleset: string; group_count: number; rule_count: number }>
}

export interface ThreatFeedEntry {
  id: number
  cidr: string
  feed_source_name: string
  added_at: string
}

// --- API functions ---

export const getSettings = () => get<Record<string, string>>("/settings/")
export const updateSettings = (settings: Record<string, string>) =>
  put<Record<string, string>>("/settings/", { settings })

export const getCVEAlerts = (params?: { severity?: string; acknowledged?: boolean }) =>
  get<CVEListResponse>(`/cve/alerts${params ? "?" + new URLSearchParams(
    Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined).map(([k, v]) => [k, String(v)]))
  ) : ""}`)
export const acknowledgeCVE = (id: number) => post<void>(`/cve/alerts/${id}/acknowledge`, {})
export const getCVEDevices = () => get<DeviceInventory[]>("/cve/devices")
export const refreshCVE = () => post<void>("/cve/refresh", {})

export const getThreatFeedSources = () => get<ThreatFeedSource[]>("/threatfeed/feeds")
export const addThreatFeedSource = (name: string, url: string) =>
  post<ThreatFeedSource>("/threatfeed/feeds", { name, url })
export const updateThreatFeedSource = (id: number, data: Partial<ThreatFeedSource>) =>
  put<ThreatFeedSource>(`/threatfeed/feeds/${id}`, data)
export const deleteThreatFeedSource = (id: number) => del(`/threatfeed/feeds/${id}`)
export const getThreatFeedStatus = () => get<ThreatFeedStatus>("/threatfeed/status")
export const getThreatFeedEntries = (params?: { page?: number; cidr?: string }) =>
  get<{ total: number; items: ThreatFeedEntry[] }>(`/threatfeed/entries${params?.cidr ? `?cidr=${encodeURIComponent(params.cidr)}` : ""}`)
export const refreshThreatFeed = () => post<void>("/threatfeed/refresh", {})
```

Note: if the existing `api.ts` doesn't have a `put` or `del` helper, add them following the same pattern as `get` and `post`.

---

## Step 12 — MCP Server Updates

In `services/mcp/server.py`, add 4 new tool functions following the existing pattern:

```python
@mcp.tool()
async def get_cve_alerts(severity: str = "", limit: int = 20) -> str:
    """List unacknowledged HIGH/CRITICAL CVE alerts for connected UniFi devices."""
    params = {"limit": limit}
    if severity:
        params["severity"] = severity
    params["acknowledged"] = "false"
    data = await _get(f"/cve/alerts", params=params)
    return json.dumps(data)

@mcp.tool()
async def get_cve_devices() -> str:
    """List UniFi device inventory with firmware versions and matched CVE counts."""
    data = await _get("/cve/devices")
    return json.dumps(data)

@mcp.tool()
async def get_threatfeed_status() -> str:
    """Get the current threat feed status — enabled state, total blocked IPs, zone rules."""
    data = await _get("/threatfeed/status")
    return json.dumps(data)

@mcp.tool()
async def get_threatfeed_entries(limit: int = 50, cidr_search: str = "") -> str:
    """Query the blocked IP/CIDR list from active threat feeds."""
    params = {"limit": limit}
    if cidr_search:
        params["cidr"] = cidr_search
    data = await _get("/threatfeed/entries", params=params)
    return json.dumps(data)
```

---

## Step 13 — `pyproject.toml` Dependency

No new dependencies required. `httpx` (already listed) handles all external HTTP. `gzip` and `ipaddress` are Python stdlib.

---

## Verification Checklist

After implementation, verify in this order:

```bash
# 1. Build succeeds
docker compose up --build -d
docker compose ps  # all services healthy

# 2. Settings API
curl http://localhost/api/v1/settings
# Expect: JSON with all default keys (cve_monitoring.enabled=false, etc.)

# 3. Enable CVE monitoring
curl -X PUT http://localhost/api/v1/settings \
  -H "Content-Type: application/json" \
  -d '{"settings": {"cve_monitoring.enabled": "true"}}'

# 4. Trigger CVE refresh and check
curl -X POST http://localhost/api/v1/cve/refresh
sleep 10
curl http://localhost/api/v1/cve/devices  # should show UniFi devices
curl http://localhost/api/v1/cve/alerts   # should show CVEs if any match

# 5. Threat feed status (disabled)
curl http://localhost/api/v1/threatfeed/feeds  # should show FireHOL L1 + Spamhaus
curl http://localhost/api/v1/threatfeed/status

# 6. Enable threat feed and trigger refresh
curl -X PUT http://localhost/api/v1/settings \
  -H "Content-Type: application/json" \
  -d '{"settings": {"threat_feed.enabled": "true"}}'
curl -X POST http://localhost/api/v1/threatfeed/refresh
sleep 30
curl http://localhost/api/v1/threatfeed/entries  # should return blocked IPs
curl http://localhost/api/v1/threatfeed/status   # should show entry count > 0

# 7. Frontend
# Open http://localhost — navigate to Settings, CVE Alerts, Threat Feeds
# All three pages should render without console errors

# 8. Minimum interval enforcement
curl -X PUT http://localhost/api/v1/settings \
  -H "Content-Type: application/json" \
  -d '{"settings": {"threat_feed.poll_interval_hours": "0"}}'
# Expect: HTTP 400
```

---

## Key Constraints (must not be violated)

- Threat feed poll minimum is **1 hour** — enforced in settings router (HTTP 400 if < 1)
- Threat feed apply mode is either **preview** or **auto**; default is preview
- In preview mode, every proposed UniFi rule/group create, update, or delete is queued for manual approval
- CVE monitoring only stores **CVSS >= 7.0** — enforced in cve_collector, not router
- Proxy setting applies to **all outbound HTTP** in both new collectors
- Disabling threat feed **deletes** all created UniFi groups/rules and clears threat_feed_entries
- **Scanner RFC1918 guard** and all existing features remain unchanged
- No new environment variables — all feature config lives in `app_settings` DB table
