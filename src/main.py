from datetime import timedelta

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_marshmallow import Marshmallow
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS

from config import ConfigFactory
from api.v1.routes import auth_app
from src.db.db_init import init_db
#from src.db.models import User


def create_app():

    app = Flask(__name__)
    app.register_blueprint(auth_app, url_prefix='/api/v1')
    bcrypt = Bcrypt(app)
    jwt = JWTManager(app)
    cors = CORS(app)

    app.config['CORS_HEADERS'] = 'Content-Type'
    app.config["JWT_COOKIE_SECURE"] = False
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']

    app.config.from_object(ConfigFactory.factory())

    init_db(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "login"

    ma = Marshmallow(app)


    class RolesSchema(ma.Schema):
        class Meta:
            fields = ("id", "name")


    role_list_schema = RolesSchema(many=False)
    role_lists_schema = RolesSchema(many=True)


    # @login_manager.user_loader
    # def load_user(user_id):
    #     return User.query.get(user_id)


    # flask swagger configs
    SWAGGER_URL = "/api/openapi"
    API_URL = "/static/swagger.yml"

    SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
        SWAGGER_URL, API_URL, config={"app_name": "Roles API"}
    )
    app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)

    return app
