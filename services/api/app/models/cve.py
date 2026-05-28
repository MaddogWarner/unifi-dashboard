from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, ForeignKey, Numeric, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class DeviceInventory(Base):
    __tablename__ = "device_inventory"

    id: Mapped[int] = mapped_column(primary_key=True)
    unifi_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    name: Mapped[str | None] = mapped_column(String(256))
    model: Mapped[str | None] = mapped_column(String(128))
    firmware_version: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    site: Mapped[str | None] = mapped_column(String(64))
    raw_json: Mapped[str | None] = mapped_column(Text)
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CVEAlert(Base):
    __tablename__ = "cve_alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    title: Mapped[str | None] = mapped_column(String(256))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(4, 1))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(32), default="nvd")
    affected_cpe: Mapped[str | None] = mapped_column(String(512))
    ubiquiti_bulletin_url: Mapped[str | None] = mapped_column(String(512))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())


class CVEDeviceLink(Base):
    __tablename__ = "cve_device_links"
    __table_args__ = (UniqueConstraint("cve_id", "device_id"),)

    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cve_alerts.cve_id", ondelete="CASCADE"), primary_key=True
    )
    device_id: Mapped[int] = mapped_column(
        ForeignKey("device_inventory.id", ondelete="CASCADE"), primary_key=True
    )
