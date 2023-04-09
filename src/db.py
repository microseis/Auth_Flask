import redis
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

redis_db = redis.Redis(host="localhost", port=6379, db=0)

db = SQLAlchemy()


def init_db(app: Flask):
    db.init_app(app)
