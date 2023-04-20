import redis
from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

from config import Config

redis_db = redis.Redis(host=Config.REDIS_HOST, port=Config.REDIS_PORT, db=0)

db = SQLAlchemy()
migrate = Migrate()


def init_db(app: Flask):
    db.init_app(app)
    Migrate(app, db)
