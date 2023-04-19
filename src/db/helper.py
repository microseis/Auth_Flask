from datetime import datetime

from flask import Flask
from pydantic import BaseModel, Field

from core.checker import bcrypt
from core.logger import logger
from db.db_init import db
from db.models import Role, User, UserRoles


def create_tables(app: Flask) -> None:
    """Подготавливаем контекст и создаём таблицы."""
    app.app_context().push()
    db.create_all()


def create_admin(admin_password: str) -> None:
    """Создание админа."""
    if not (
        db.session.query(User)
        .filter(User.id == UserRoles.user_id)
        .filter(Role.id == UserRoles.role_id)
        .first()
    ):
        admin = User(
            login="admin",
            password=bcrypt.generate_password_hash(admin_password).decode(
                "utf-8",
            ),
        )
        admin.roles.append(Role(name="Admin", is_superuser=True))

        db.session.add(admin)
        db.session.commit()

    admins = (
        db.session.query(User)
        .filter(User.id == UserRoles.user_id)
        .filter(Role.id == UserRoles.role_id)
        .all()
    )
    logger.info("List of admins:")
    if admins:
        for admin_user in admins:
            logger.info("Admin: %s", admin_user.login)


class RegisterUser(BaseModel):
    login: str = Field(min_length=3)
    password: str = Field(min_length=3)


class LoginUser(RegisterUser):
    pass


class UserTokens(BaseModel):
    access_token: str
    refresh_token: str


class AccessToken(BaseModel):
    access_token: str


class RolesData(BaseModel):
    name: str
    is_superuser: bool
    is_privileged: bool


class UserData(BaseModel):
    login: str


class UserRoleData(BaseModel):
    role_name: str


class PasswordData(BaseModel):
    old_password: str = Field(min_length=3)
    new_password: str = Field(min_length=3)


class UserHistory(BaseModel):
    date_logged_in: datetime
    ip_address: str
    user_agent: str


class Message(BaseModel):
    result: str
