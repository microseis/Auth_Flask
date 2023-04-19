import uuid
from functools import wraps

from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt, get_jwt_identity, jwt_required)
from pydantic.tools import lru_cache

from core.checker import Checker
from core.logger import logger
from db.db_init import redis_db
from db.db_service import DbService
from db.helper import LoginUser, PasswordData, RegisterUser
from db.models import User, UserHistory
from service.role_service import RoleService


class UserService:
    def __init__(self, checker: Checker, db_service: DbService):
        self.checker = checker
        self.db_service = db_service

    def register_user(self, user_data: RegisterUser):
        check_result = self.checker.login_check(user_data.login)
        if not check_result.get("login_ok"):
            raise BadLoginError
        created = self.db_service.add_user(
            User(
                login=user_data.login,
                password=self.checker.hash_password(user_data.password),
            )
        )
        if not created:
            raise UserExistsError
        return {"result": created}

    def login_user(self, user_data: LoginUser, user_ip: str, user_agent: str) -> User:
        user = self.db_service.is_user_login_exist(user_data.login)
        if not user:
            raise BadLoginError
        if not self.checker.check_password_hash(user.password, user_data.password):
            raise WrongPasswordError
        self.db_service.add_history(user.id, user_ip, user_agent)
        return user

    def password_change(self, user_id, password_data: PasswordData):
        user = self.db_service.is_user_id_exist(user_id)
        logger.info("Identity: %s", user_id)
        if not user:
            raise BadLoginError
        if not self.checker.check_password_hash(
            user.password, password_data.old_password
        ):
            raise WrongPasswordError
        hashed = self.checker.hash_password(password_data.new_password)
        changed = self.db_service.change_password(user, hashed)
        if not changed:
            raise BadPasswordError
        return changed

    @staticmethod
    def get_tokens(user_id: str) -> [str, str]:
        access_token = create_access_token(identity=user_id)
        refresh_token = create_refresh_token(user_id)

        redis_db.set(name=str(user_id), value=refresh_token, ex=3600)

        return access_token, refresh_token

    @staticmethod
    def user_logout() -> dict:
        token = get_jwt()
        current_user = get_jwt_identity()
        logger.info(current_user)
        logger.info(token)
        return token

    def get_user_history(self, identity: uuid):
        history: list = self.db_service.get_history(identity)
        if not history:
            raise NoUserHistoryError
        history_list = []
        for h in history:
            history_list.append(
                {
                    "ip": h.ip_address,
                    "usr_agent": h.user_agent,
                    "date_logged_in": h.date_logged_in,
                }
            )
        return history_list


@lru_cache()
def get_user_service():
    return UserService(Checker(), DbService())


def for_admins():
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_role = RoleService(DbService()).get_user_role_by_id(get_jwt_identity())
            if user_role.get("name") == "Admin":
                return func(*args, **kwargs)
            else:
                raise PermissionError("Permission Error")

        return wrapper

    return decorator


class UserExistsError(Exception):
    pass


class BadLoginError(Exception):
    pass


class WrongPasswordError(Exception):
    pass


class BadPasswordError(Exception):
    pass


class NoUserHistoryError(Exception):
    pass
