from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_marshmallow import Marshmallow
from flask_swagger_ui import get_swaggerui_blueprint

from config import ConfigFactory
from db import init_db
from db_models import User

app = Flask(__name__)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
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


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# flask swagger configs
SWAGGER_URL = "/api/openapi"
API_URL = "/static/swagger.yml"

SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL, API_URL, config={"app_name": "Roles API"}
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)
