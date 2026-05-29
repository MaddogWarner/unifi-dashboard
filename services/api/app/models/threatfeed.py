from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ThreatFeedSource(Base):
    __tablename__ = "threat_feed_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    url: Mapped[str] = mapped_column(String(1024), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_entry_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())


class ThreatFeedEntry(Base):
    __tablename__ = "threat_feed_entries"
    __table_args__ = (UniqueConstraint("cidr", "feed_source_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    feed_source_id: Mapped[int] = mapped_column(
        ForeignKey("threat_feed_sources.id", ondelete="CASCADE")
    )
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())


class ThreatFeedRule(Base):
    __tablename__ = "threat_feed_rules"
    __table_args__ = (UniqueConstraint("ruleset", "chunk_index"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ruleset: Mapped[str] = mapped_column(String(64), nullable=False)
    group_unifi_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rule_unifi_id: Mapped[str | None] = mapped_column(String(128))
    chunk_index: Mapped[int] = mapped_column(Integer, default=0)
    payload_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now()
    )


class ThreatFeedPendingRule(Base):
    __tablename__ = "threat_feed_pending_rules"
    __table_args__ = (UniqueConstraint("ruleset", "chunk_index", "action", "payload_hash", "status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ruleset: Mapped[str] = mapped_column(String(64), nullable=False)
    chunk_index: Mapped[int] = mapped_column(Integer, default=0)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    group_name: Mapped[str] = mapped_column(String(256), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(256), nullable=False)
    group_unifi_id: Mapped[str | None] = mapped_column(String(128))
    rule_unifi_id: Mapped[str | None] = mapped_column(String(128))
    entry_count: Mapped[int] = mapped_column(Integer, default=0)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
