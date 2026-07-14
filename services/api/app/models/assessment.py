from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AssessmentRun(Base):
    __tablename__ = "assessment_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    score: Mapped[int] = mapped_column(Integer)
    pass_count: Mapped[int] = mapped_column(Integer)
    warn_count: Mapped[int] = mapped_column(Integer)
    fail_count: Mapped[int] = mapped_column(Integer)
    status_hash: Mapped[str] = mapped_column(String(64))
    checks_json: Mapped[str] = mapped_column(Text)
