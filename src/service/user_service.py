from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt, get_jwt_identity)
from pydantic.tools import lru_cache

from db.models import User
from src.core.checker import Checker
from src.core.logger import logger
from src.db.db_service import DbService
from src.db.helper import RegisterUser


class UserService:
    def __init__(self, checker: Checker, db_service: DbService):
        self.checker = checker
        self.db_service = db_service

    def register_user(self, user_data: RegisterUser):
        check_result = self.checker.login_check(user_data.login)
        if not check_result.get("login_ok"):
            raise BadLoginError
        if not self.db_service.add(
            User(
                login=user_data.login,
                password=self.checker.hash_password(user_data.password),
            )
        ):
            raise UserExistsError

    def sign_up_user(self, user_data) -> User:
        user = User.query.filter(User.login == user_data.login).first()
        if not user:
            raise BadLoginError
        if not self.checker.check_password_hash(user.password, user_data.password):
            raise WrongPasswordError
        return user

    @staticmethod
    def get_tokens(user: User) -> [str, str]:
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(user.id)
        # user_session = UserHistory(user_id=user.id)
        # db.session.add(user_session)
        # redis_db.set(name=str(user.id), value=refresh_token, ex=3600)
        # db.session.commit()
        return access_token, refresh_token

    @staticmethod
    def user_logout():
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
