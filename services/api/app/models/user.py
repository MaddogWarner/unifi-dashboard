from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class User(SQLAlchemyBaseUserTableUUID, Base):
    theme: Mapped[str] = mapped_column(String(16), nullable=False, server_default="light")
