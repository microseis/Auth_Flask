from pydantic.tools import lru_cache

from db.models import User
from src.core.checker import Checker
from src.db.helper import RegisterUser
from src.db.db_service import DbService


class UserService:
    def __init__(self, checker: Checker, db_service: DbService):
        self.checker = checker
        self.db_service = db_service

    def register_user(self, user_data: RegisterUser):
        check_result = self.checker.login_check(user_data.login)
        if not check_result.get('login_ok'):
            raise BadLoginError
        if not self.db_service.add(User(
            login=user_data.login,
            password=self.checker.hash_password(user_data.password))):
            raise UserExistsError


@lru_cache()
def get_user_service():
    return UserService(Checker(), DbService())


class UserExistsError(Exception):
    pass


class BadLoginError(Exception):
    pass
