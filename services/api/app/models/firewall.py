from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class FirewallPolicy(Base):
    __tablename__ = "firewall_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    unifi_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(256))
    action: Mapped[str] = mapped_column(String(16))
    src_zone: Mapped[str | None] = mapped_column(String(64))
    dst_zone: Mapped[str | None] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    protocol: Mapped[str | None] = mapped_column(String(16))
    schedule: Mapped[str | None] = mapped_column(String(64))
    raw_json: Mapped[str] = mapped_column(Text)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    logs: Mapped[list["FirewallLog"]] = relationship(back_populates="policy")


class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    unifi_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(256))
    action: Mapped[str] = mapped_column(String(16))
    ruleset: Mapped[str | None] = mapped_column(String(32))
    rule_index: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    src_address: Mapped[str | None] = mapped_column(String(256))
    dst_address: Mapped[str | None] = mapped_column(String(256))
    protocol: Mapped[str | None] = mapped_column(String(16))
    dst_port: Mapped[str | None] = mapped_column(String(128))
    raw_json: Mapped[str] = mapped_column(Text)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class FirewallLog(Base):
    __tablename__ = "firewall_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    rule_name: Mapped[str | None] = mapped_column(String(256), index=True)
    action: Mapped[str] = mapped_column(String(8))
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(8))
    interface: Mapped[str | None] = mapped_column(String(32))
    direction: Mapped[str | None] = mapped_column(String(16))
    matched_policy_id: Mapped[int | None] = mapped_column(ForeignKey("firewall_policies.id"))
    raw_line: Mapped[str] = mapped_column(Text)

    policy: Mapped["FirewallPolicy | None"] = relationship(back_populates="logs")


class PolicySnapshot(Base):
    __tablename__ = "policy_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_type: Mapped[str] = mapped_column(String(32))
    snapshot_hash: Mapped[str] = mapped_column(String(64))
    snapshot_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
