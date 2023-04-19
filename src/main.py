from datetime import timedelta

import click
from flask import Flask
from flask_jwt_extended import JWTManager

from api import api
from api.v1.routes import auth_app
from config import ConfigFactory
from db.db_init import init_db
from db.helper import create_admin, create_tables


def create_app():
    app = Flask(__name__)
    app.config.from_object(ConfigFactory.factory())
    JWTManager(app)
    app.config["JWT_TOKEN_LOCATION"] = ["headers"]
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

    init_db(app)

    app.register_blueprint(auth_app, url_prefix="/api/v1")
    api.register(app)

    @click.option("--admin_password")
    @app.cli.command()
    def createsuperuser(admin_password):
        """Create admin/superuser"""
        click.echo("Creating the admin if not exist..")
        create_admin(admin_password)

    @app.cli.command()
    def createdbtables(app):
        """Create tables"""
        click.echo("Creating tables if not exist..")
        create_tables(app)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(
        debug=True,
        host="0.0.0.0",
        port=8000,
    )
