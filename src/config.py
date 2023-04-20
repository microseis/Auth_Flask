import os
from functools import lru_cache

from dotenv import load_dotenv
from pydantic import BaseSettings

from core.logger import logger

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, "../.env"))


class Settings(BaseSettings):
    @staticmethod
    def factory():
        env = os.environ.get("ENV", "development")
        logger.info("ENV settings are taken from: %s", env)
        if env == "development":
            return Development()
        elif env == "docker":
            return Docker()
        elif env == "production":
            return Production()


class Config:

    """Base config."""

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get("SECRET_KEY")
    REDIS_HOST = os.environ.get("REDIS_HOST")
    REDIS_PORT = int(os.environ.get("REDIS_PORT"))


class Development(Config):
    DEBUG = True
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI")


class Docker(Config):
    DEBUG = True
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_DOCKER_URI")


class Production(Config):
    DEBUG = True
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI")


@lru_cache()
def get_settings() -> Settings:
    return Settings()
