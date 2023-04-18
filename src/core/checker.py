import re
from abc import ABC, abstractmethod

from flask import Flask
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)


class AbstractChecker(ABC):
    @abstractmethod
    def hash_password(self, password: str):
        pass

    @abstractmethod
    def check_password_hash(self, hashed: str, password: str):
        pass

    def login_check(self, login: str):
        pass


class Checker(AbstractChecker):
    def hash_password(self, password: str) -> str:
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        return hashed_password

    def check_password_hash(self, hashed_password: str, password: str) -> bool:
        return bcrypt.check_password_hash(hashed_password, password)

    def login_check(self, login: str) -> dict:
        # searching for symbols
        symbol_error = re.search("^[A-Za-z][A-Za-z0-9_.]*$", login) is None

        # overall result
        login_ok = not symbol_error

        return {
            "login_ok": login_ok,
            "symbol_error": symbol_error,
        }
