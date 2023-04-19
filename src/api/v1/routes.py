import uuid

from flask import Blueprint, abort, jsonify, make_response, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from spectree import Response

from api import api
from core.logger import logger
from db.db_init import redis_db
from db.helper import (AccessToken, LoginUser, RegisterUser, RolesData,
                       UserData, UserRoleData, UserTokens)
from service.role_service import RoleService, get_role_service
from service.user_service import (BadLoginError, UserExistsError, UserService,
                                  get_user_service)

role_service: RoleService = get_role_service()
user_service: UserService = get_user_service()

auth_app = Blueprint("Auth", __name__)


@auth_app.route("/register", methods=["POST"])
@api.validate(
    json=RegisterUser, resp=Response("HTTP_400", HTTP_200=RegisterUser), tags=["Auth"]
)
def register_user():
    try:
        user_data = RegisterUser(**request.json)
        logger.info(user_data)
        user_service.register_user(user_data)
        return jsonify(user_data.dict())
    except UserExistsError:
        raise abort(409)
    except BadLoginError:
        raise abort(400)


@auth_app.route("/sign_in", methods=["POST"])
@api.validate(
    json=LoginUser, resp=Response("HTTP_400", HTTP_200=UserTokens), tags=["Auth"]
)
def sign_in():
    user_data = LoginUser(**request.json)
    user = user_service.sign_up_user(user_data)
    if not user:
        raise abort(409)

    access_token, refresh_token = user_service.get_tokens(user)
    return jsonify(
        UserTokens(access_token=access_token, refresh_token=refresh_token).dict()
    )


@auth_app.route("/user_logout", methods=["POST"])
@jwt_required()
@api.validate(tags=["Auth"], security={"Bearer": []})
def user_logout():
    old_token = user_service.user_logout()
    if not old_token:
        raise abort(409)
    return {"message": "User has logged out"}


@auth_app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
@api.validate(resp=Response("HTTP_400", HTTP_200=AccessToken), tags=["Auth"])
def refresh():
    # We are using the `refresh=True` options in jwt_required to only allow
    # refresh tokens to access this route.
    identity = get_jwt_identity()
    access_token, refresh_token = user_service.get_tokens(identity)
    redis_db.set(name=str(identity), value=refresh_token, ex=3600)
    return make_response(jsonify(access_token=access_token), 200)


@auth_app.route("/roles", methods=["GET"])
@api.validate(tags=["Role"], resp=Response("HTTP_400"))
def get_all_roles():
    output = role_service.get_all_roles()
    if not output:
        raise abort(400)
    return output


@auth_app.route("/roles/<id>", methods=["GET"])
@api.validate(resp=Response("HTTP_400", HTTP_200=RolesData), tags=["Role"])
def get_role_by_id(id: uuid):
    role = role_service.get_role_by_id(id)
    if not role:
        raise abort(400)
    return role


@auth_app.route("/roles/<id>", methods=["PUT"])
@api.validate(
    json=RolesData, resp=Response("HTTP_400", HTTP_200=RolesData), tags=["Role"]
)
def update_role_by_id(id: uuid):
    role_data = RolesData(**request.json)
    role = role_service.update_role_by_id(id, role_data)
    if not role:
        raise abort(400)
    return role


@auth_app.route("/roles", methods=["POST"])
@api.validate(json=RolesData, resp=Response("HTTP_400"), tags=["Role"])
def add_role() -> dict:
    role_data = RolesData(**request.json)
    result = role_service.add_role(role_data)
    if not result:
        raise abort(400)
    return result


@auth_app.route("/roles/<id>", methods=["DELETE"])
@api.validate(json=RolesData, resp=Response("HTTP_400"), tags=["Role"])
def delete_role(id: uuid) -> dict:
    result = role_service.delete_role_by_id(id)
    if not result:
        raise abort(400)
    return result


@auth_app.route("/users/<id>", methods=["DELETE"])
@api.validate(json=UserData, resp=Response("HTTP_400"), tags=["User Management"])
def delete_user_role_by_id(id: uuid):
    result = role_service.delete_user_role_by_id(id)
    if not result:
        raise abort(400)
    return result


@auth_app.route("/users/<user_id>", methods=["PUT"])
@api.validate(json=UserRoleData, resp=Response("HTTP_400"), tags=["User Management"])
def update_user_role_by_id(user_id: uuid):
    role_data = UserRoleData(**request.json)
    result = role_service.update_user_role_by_id(user_id, role_data)
    if not result:
        raise abort(400)
    return result


@auth_app.errorhandler(400)
def handle_400_error(_error) -> Response:
    """Return a http 400 error to client"""
    return make_response(jsonify({"error": "Bad request"}), 400)


@auth_app.errorhandler(401)
def handle_401_error(_error) -> Response:
    """Return a http 401 error to client"""
    return make_response(jsonify({"error": "Unauthorised"}), 401)


@auth_app.errorhandler(404)
def handle_404_error(_error) -> Response:
    """Return a http 404 error to client"""
    return make_response(jsonify({"error": "Not found"}), 404)


@auth_app.errorhandler(409)
def handle_409_error(_error) -> Response:
    """Return a http 409 error to client"""
    return make_response(jsonify({"error": "User already exists"}), 409)


@auth_app.errorhandler(500)
def handle_500_error(_error) -> Response:
    """Return a http 500 error to client"""
    return make_response(jsonify({"error": "Server error"}), 500)
