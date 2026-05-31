import os
import uuid
from collections.abc import AsyncIterator
from typing import Optional

from fastapi import Depends, Request
from fastapi_users import BaseUserManager, FastAPIUsers, UUIDIDMixin
from fastapi_users.authentication import AuthenticationBackend, BearerTransport, JWTStrategy
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users.exceptions import InvalidPasswordException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User

AUTH_SECRET: str = os.environ["AUTH_SECRET"]
TOKEN_LIFETIME: int = int(os.getenv("AUTH_TOKEN_LIFETIME_SECONDS", str(60 * 60 * 24)))


async def get_user_db(
    session: AsyncSession = Depends(get_db),
) -> AsyncIterator[SQLAlchemyUserDatabase]:
    yield SQLAlchemyUserDatabase(session, User)


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = AUTH_SECRET
    verification_token_secret = AUTH_SECRET

    async def on_after_register(self, user: User, request: Optional[Request] = None) -> None:
        count = await self.user_db.session.scalar(select(func.count()).select_from(User))
        if count == 1:
            user.is_superuser = True
            await self.user_db.session.commit()
            await self.user_db.session.refresh(user)

    async def validate_password(self, password: str, user: Optional[User] = None) -> None:
        if len(password) < 12:
            raise InvalidPasswordException(reason="Password must be at least 12 characters")


async def get_user_manager(user_db=Depends(get_user_db)):
    yield UserManager(user_db)


bearer_transport = BearerTransport(tokenUrl="/api/v1/auth/login")


def get_jwt_strategy() -> JWTStrategy:
    return JWTStrategy(secret=AUTH_SECRET, lifetime_seconds=TOKEN_LIFETIME)


auth_backend = AuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy,
)

fastapi_users = FastAPIUsers[User, uuid.UUID](get_user_manager, [auth_backend])

current_active_user = fastapi_users.current_user(active=True)
current_superuser = fastapi_users.current_user(active=True, superuser=True)
