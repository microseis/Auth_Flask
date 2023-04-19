import uuid
from functools import lru_cache

from core.logger import logger
from db.db_service import DbService
from db.helper import RolesData


class RoleService:
    def __init__(self, db_service: DbService):
        self.db_service = db_service

    def get_all_roles(self) -> list:
        roles = self.db_service.get_roles_from_db()
        output = []
        for item in roles:
            role_data = {
                "name": item.name,
                "is_superuser": item.is_superuser,
                "is_privileged": item.is_privileged,
            }
            output.append(role_data)
        return output

    def add_role(self, role_info: RolesData) -> dict:
        role = self.db_service.add_new_role(role_info)
        return {
            "name": role.name,
            "is_superuser": role.is_superuser,
            "is_privileged": role.is_privileged,
        }

    def get_role_by_id(self, role_id: str) -> dict:
        role = self.db_service.get_role_by_id(role_id)
        return {
            "name": role.name,
            "is_superuser": role.is_superuser,
            "is_privileged": role.is_privileged,
        }

    def get_user_role_by_id(self, user_id: uuid) -> dict:
        user_role = self.db_service.get_user_role_by_id(user_id)
        logger.info("user role: %s", user_role)
        if user_role:
            return {
                "name": user_role.name,
                "is_superuser": user_role.is_superuser,
                "is_privileged": user_role.is_privileged,
            }

    def update_role_by_id(self, role_id: str, request) -> dict:
        role = self.db_service.update_role_by_id(role_id, request=request)
        return {
            "name": role.name,
            "is_superuser": role.is_superuser,
            "is_privileged": role.is_privileged,
        }

    def delete_role_by_id(self, role_id: str) -> dict:
        role = self.db_service.delete_role_by_id(role_id)
        if role is not None:
            return {"role_id": role.id, "result": "Role deleted"}
        else:
            return {"error": "There is no such role"}

    def delete_user_role_by_id(self, role_id: str) -> dict:
        user_role = self.db_service.delete_user_role_by_id(role_id)
        if user_role is not None:
            return {"user_id": user_role.user_id, "result": "Role deleted"}
        else:
            return {"error": "The user has no any role"}

    def update_user_role_by_id(self, role_id: str, role_data) -> dict:
        role = self.db_service.update_user_role_by_id(role_id, role_data)
        if role is not None:
            return {"role_id": role.id, "result": "User role has been updated"}
        else:
            return {"error": "There is no such role"}


@lru_cache()
def get_role_service():
    return RoleService(DbService())
