from functools import lru_cache

from db.db_service import DbService


class RoleService:
    def __init__(self, db_service: DbService):
        self.db_service = db_service

    def get_all_roles(self):
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

    def get_role_by_id(self, role_id):
        role = self.db_service.get_role_by_id(role_id)
        return {
            "name": role.name,
            "is_superuser": role.is_superuser,
            "is_privileged": role.is_privileged,
        }

    def update_role_by_id(self, role_id, request):
        role = self.db_service.update_role_by_id(role_id, request=request)
        return {
            "name": role.name,
            "is_superuser": role.is_superuser,
            "is_privileged": role.is_privileged,
        }

    def delete_user_role_by_id(self, role_id):
        user_role = self.db_service.delete_user_role_by_id(role_id)
        if user_role is not None:
            return {"user_id": user_role.user_id, "result": "Role deleted"}
        else:
            return {"error": "The user has no any role"}

    def delete_role_by_id(self, role_id):
        role = self.db_service.delete_role_by_id(role_id)
        if role is not None:
            return {"role_id": role.id, "result": "Role deleted"}
        else:
            return {"error": "There is no such role"}


@lru_cache()
def get_role_service():
    return RoleService(DbService())
