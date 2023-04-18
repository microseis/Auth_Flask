import os

import redis
from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

redis_db = redis.Redis(
    host=os.environ.get("REDIS_HOST"), port=int(os.environ.get("REDIS_PORT")), db=0
)

db = SQLAlchemy()


def init_db(app: Flask):
    db.init_app(app)
    Migrate(app, db)
