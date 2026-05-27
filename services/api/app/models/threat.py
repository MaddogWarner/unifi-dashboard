from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    signature_id: Mapped[str | None] = mapped_column(String(64))
    signature_name: Mapped[str | None] = mapped_column(String(256))
    category: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str | None] = mapped_column(String(16))
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    action: Mapped[str | None] = mapped_column(String(16))
    raw_json: Mapped[str] = mapped_column(Text)
