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
    def add_new_role(role_data) -> Optional[Role]:
        if not Role.query.filter(Role.name == role_data.name).first():
            role = Role(
                name=role_data.name,
                is_superuser=role_data.is_superuser,
                is_privileged=role_data.is_privileged,
            )
            db.session.add(role)
            db.session.commit()
            return role

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

    @staticmethod
    def update_user_role_by_id(user_id, request):
        logger.info("Requested Role: %s", request.role_name)
        logger.info("User ID: %s", user_id)
        user_role = UserRoles.query.filter_by(user_id=user_id).first()
        if user_role is not None:
            role = Role.query.filter_by(id=user_role.role_id).first()
            logger.info("The user has existing role: %s", role.name)
            role_check = Role.query.filter_by(name=request.role_name).first()
            if role_check:
                logger.info("Proposed role %s exists in database", role_check.name)
                user_role.role_id = role_check.id
                user_role.user_id = user_id
                db.session.commit()
                return user_role

            else:
                logger.info("No such role")
        else:
            logger.info("The user has no existing role")
            role_check = Role.query.filter_by(name=request.role_name).first()

            if role_check:
                logger.info("Proposed role %s exists in database", role_check.name)
                new_user_role = UserRoles()
                new_user_role.role_id = role_check.id
                new_user_role.user_id = user_id
                db.session.add(new_user_role)
                db.session.commit()
                return new_user_role
            else:
                logger.info("No such role")
