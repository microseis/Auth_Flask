from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt, get_jwt_identity)
from pydantic.tools import lru_cache

from core.checker import Checker
from core.logger import logger
from db.db_service import DbService
from db.helper import LoginUser, PasswordData, RegisterUser
from db.models import User


class UserService:
    def __init__(self, checker: Checker, db_service: DbService):
        self.checker = checker
        self.db_service = db_service

    def register_user(self, user_data: RegisterUser):
        check_result = self.checker.login_check(user_data.login)
        if not check_result.get("login_ok"):
            raise BadLoginError
        if not self.db_service.add_user(
            User(
                login=user_data.login,
                password=self.checker.hash_password(user_data.password),
            )
        ):
            raise UserExistsError

    def login_user(self, user_data: LoginUser) -> User:
        user = self.db_service.is_user_login_exist(user_data.login)
        if not user:
            raise BadLoginError
        if not self.checker.check_password_hash(user.password, user_data.password):
            raise WrongPasswordError
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
        # user_session = UserHistory(user_id=user.id)
        # db.session.add(user_session)
        # redis_db.set(name=str(user.id), value=refresh_token, ex=3600)
        # db.session.commit()
        return access_token, refresh_token

    @staticmethod
    def user_logout() -> dict:
        token = get_jwt()
        current_user = get_jwt_identity()
        logger.info(current_user)
        logger.info(token)
        return token


@lru_cache()
def get_user_service():
    return UserService(Checker(), DbService())


class UserExistsError(Exception):
    pass


class BadLoginError(Exception):
    pass


class WrongPasswordError(Exception):
    pass


class BadPasswordError(Exception):
    pass
