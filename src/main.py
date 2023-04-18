from datetime import timedelta

from flask import Flask
from flask_jwt_extended import JWTManager

from api.v1.routes import auth_app
from config import ConfigFactory
from src.api import spec
from src.db.db_init import init_db


def create_app():
    app = Flask(__name__)
    app.config.from_object(ConfigFactory.factory())
    JWTManager(app)
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

    init_db(app)

    app.register_blueprint(auth_app, url_prefix="/api/v1")
    spec.register(app)
    return app


if __name__ == "__main__":
    app = create_app()
    app.run(
        debug=True,
        host="0.0.0.0",
        port=8000,
    )
