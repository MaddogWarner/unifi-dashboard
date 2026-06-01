import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_active_user, current_superuser, get_user_manager
from app.database import get_db
from app.models.user import User
from app.schemas.user import UserCreate

router = APIRouter()


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class UserCreateRequest(BaseModel):
    email: str
    password: str


class UserInfo(BaseModel):
    id: uuid.UUID
    email: str
    is_active: bool
    is_superuser: bool
    theme: str = "light"
    model_config = ConfigDict(from_attributes=True)


class MeUpdateRequest(BaseModel):
    theme: str


@router.get("/setup-status")
async def setup_status(db: AsyncSession = Depends(get_db)) -> dict[str, bool]:
    count = await db.scalar(select(func.count()).select_from(User))
    return {"configured": (count or 0) > 0}


@router.get("/me", response_model=UserInfo)
async def get_me(user: User = Depends(current_active_user)) -> UserInfo:
    return UserInfo.model_validate(user)


@router.patch("/me", response_model=UserInfo, status_code=status.HTTP_200_OK)
async def update_me(
    body: MeUpdateRequest,
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> UserInfo:
    if body.theme not in ("light", "dark"):
        raise HTTPException(status_code=400, detail="theme must be 'light' or 'dark'")
    await db.execute(update(User).where(User.id == user.id).values(theme=body.theme))
    await db.commit()
    updated = await db.scalar(select(User).where(User.id == user.id))
    return UserInfo.model_validate(updated)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: PasswordChangeRequest,
    user: User = Depends(current_active_user),
    user_manager=Depends(get_user_manager),
) -> Response:
    verified, _ = user_manager.password_helper.verify_and_update(
        body.current_password, user.hashed_password
    )
    if not verified:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(body.new_password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    await user_manager.user_db.session.execute(
        update(User)
        .where(User.id == user.id)
        .values(hashed_password=user_manager.password_helper.hash(body.new_password))
    )
    await user_manager.user_db.session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/users", response_model=list[UserInfo])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_superuser),
) -> list[UserInfo]:
    result = await db.execute(select(User).order_by(User.email))
    return [UserInfo.model_validate(user) for user in result.scalars().all()]


@router.post("/users", response_model=UserInfo, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreateRequest,
    _: User = Depends(current_superuser),
    user_manager=Depends(get_user_manager),
) -> UserInfo:
    from fastapi_users.exceptions import UserAlreadyExists

    try:
        new_user = await user_manager.create(
            UserCreate(email=body.email, password=body.password, is_active=True),
            safe=True,
        )
    except UserAlreadyExists as exc:
        raise HTTPException(
            status_code=400, detail="A user with that email already exists"
        ) from exc
    return UserInfo.model_validate(new_user)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID,
    current_user: User = Depends(current_superuser),
    user_manager=Depends(get_user_manager),
) -> Response:
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    user = await user_manager.user_db.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_superuser:
        superuser_count = await user_manager.user_db.session.scalar(
            select(func.count()).select_from(User).where(User.is_superuser.is_(True))
        )
        if (superuser_count or 0) <= 1:
            raise HTTPException(status_code=400, detail="Cannot delete the last superuser")
    await user_manager.user_db.delete(user)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
