import uuid
from typing import Optional

from core.logger import logger
from db.db_init import db
from db.models import Role, User, UserRoles


class DbService:
    @staticmethod
    def add_user(instance: db.Model) -> str:
        try:
            db.session.add(instance)
            db.session.commit()
            return "User created"
        except Exception as e:
            logger.info(e)

    @staticmethod
    def is_user_exist(user_data) -> Optional[User]:
        return User.query.filter(User.login == user_data.login).first()

    @staticmethod
    def get_roles_from_db() -> Optional[Role]:
        return Role.query.all()

    @staticmethod
    def get_role_by_id(role_id: uuid) -> Optional[Role]:
        return Role.query.get_or_404(role_id)

    @staticmethod
    def update_role_by_id(role_id: uuid, request) -> Optional[Role]:
        role = Role.query.get_or_404(role_id)
        if role:
            role.name = request.name
            role.is_privileged = request.is_privileged
            role.is_superuser = request.is_superuser
            db.session.commit()
            return role

    @staticmethod
    def delete_role_by_id(role_id: uuid) -> Optional[Role]:
        role = Role.query.get(role_id)
        if role is not None:
            db.session.delete(role)
            db.session.commit()
        return role

    @staticmethod
    def delete_user_role_by_id(user_id: uuid) -> Optional[UserRoles]:
        user_role = UserRoles.query.filter_by(user_id=user_id).first()
        if user_role is not None:
            db.session.delete(user_role)
            db.session.commit()
        return user_role
