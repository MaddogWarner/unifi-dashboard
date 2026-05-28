from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Network(Base):
    __tablename__ = "networks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    unifi_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(256))
    vlan_id: Mapped[int | None] = mapped_column(Integer)
    zone: Mapped[str | None] = mapped_column(String(64))
    subnet: Mapped[str | None] = mapped_column(String(64))
    purpose: Mapped[str | None] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    raw_json: Mapped[str] = mapped_column(Text)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IdsConfig(Base):
    __tablename__ = "ids_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mode: Mapped[str | None] = mapped_column(String(32))
    categories: Mapped[str | None] = mapped_column(Text)
    sensitivity: Mapped[str | None] = mapped_column(String(16))
    raw_json: Mapped[str | None] = mapped_column(Text)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
