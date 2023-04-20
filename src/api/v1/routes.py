import uuid
from http import HTTPStatus

from flask import Blueprint, abort, jsonify, make_response, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from spectree import Response

from core import api
from db.helper import (AccessToken, LoginUser, Message, PasswordData,
                       RegisterUser, RolesData, UserData, UserRoleData,
                       UserTokens)
from service.role_service import RoleService, get_role_service
from service.user_service import (BadLoginError, UserExistsError, UserService,
                                  WrongPasswordError, for_admins,
                                  get_user_service)

role_service: RoleService = get_role_service()
user_service: UserService = get_user_service()

auth_app = Blueprint("Auth", __name__)


@auth_app.route("/register", methods=["POST"])
@api.validate(
    json=RegisterUser, resp=Response("HTTP_400", HTTP_200=Message), tags=["Auth"]
)
def register_user():
    """Регистрация пользователя"""
    try:
        user_data = RegisterUser(**request.json)
        result = user_service.register_user(user_data)
        return jsonify(result)
    except UserExistsError:
        raise abort(HTTPStatus.CONFLICT)
    except BadLoginError:
        raise abort(HTTPStatus.BAD_REQUEST)


@auth_app.route("/login", methods=["POST"])
@api.validate(
    json=LoginUser, resp=Response("HTTP_400", HTTP_200=UserTokens), tags=["Auth"]
)
def login():
    """Вход пользователя в аккаунт"""
    user_data = LoginUser(**request.json)
    try:
        user = user_service.login_user(
            user_data, request.remote_addr, str(request.user_agent)
        )
        access_token, refresh_token = user_service.get_tokens(user.id)
        return make_response(
            jsonify(
                UserTokens(
                    access_token=access_token, refresh_token=refresh_token
                ).dict()
            ),
            HTTPStatus.OK,
        )
    except BadLoginError:
        abort(HTTPStatus.UNAUTHORIZED)

    except WrongPasswordError:
        abort(HTTPStatus.FORBIDDEN)


@auth_app.route("/user_history", methods=["GET"])
@api.validate(tags=["Auth"])
@jwt_required()
def get_user_history():
    """Получение истории входов в аккаунт"""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per-page", 2, type=int)

    identity: uuid = get_jwt_identity()
    history = user_service.get_user_history(identity, page, per_page)
    if not history:
        raise abort(HTTPStatus.BAD_REQUEST)
    return jsonify(history)


@auth_app.route("/user_logout", methods=["POST"])
@jwt_required()
@api.validate(tags=["Auth"], security={"Bearer": []})
def user_logout():
    """Выход пользователя из аккаунта"""
    old_token = user_service.user_logout()
    if not old_token:
        raise abort(HTTPStatus.CONFLICT)
    return {"message": "User has logged out"}


@auth_app.route("/change_password", methods=["POST"])
@jwt_required()
@api.validate(json=PasswordData, tags=["Auth"], security={"Bearer": []})
def change_password():
    """Изменение пароля пользователя"""
    try:
        password_data = PasswordData(**request.json)
        result = user_service.password_change(
            user_id=get_jwt_identity(), password_data=password_data
        )
        return make_response(jsonify(result), HTTPStatus.OK)
    except BadLoginError:
        abort(HTTPStatus.BAD_REQUEST)
    except WrongPasswordError:
        abort(HTTPStatus.FORBIDDEN)


@auth_app.route("/refresh", methods=["POST"])
@jwt_required(refresh=False)
@api.validate(
    resp=Response("HTTP_400", HTTP_200=AccessToken),
    tags=["Auth"],
    security={"Bearer": []},
)
def refresh():
    """Обновление access-токена"""
    # We are using the `refresh=True` options in jwt_required to only allow
    # refresh tokens to access this route.
    identity = get_jwt_identity()
    access_token, refresh_token = user_service.get_tokens(identity)
    return make_response(jsonify(access_token=access_token), HTTPStatus.OK)


@auth_app.route("/roles", methods=["GET"])
@api.validate(tags=["Role"], resp=Response("HTTP_400"))
@jwt_required()
@for_admins()
def get_all_roles():
    """Получение списка всех ролей"""
    try:
        output = role_service.get_all_roles()
        if not output:
            raise abort(HTTPStatus.BAD_REQUEST)
        return output
    except PermissionError:
        raise abort(HTTPStatus.FORBIDDEN)


@auth_app.route("/roles/<id>", methods=["GET"])
@api.validate(resp=Response("HTTP_400", HTTP_200=RolesData), tags=["Role"])
@jwt_required()
@for_admins()
def get_role_by_id(id: uuid):
    """Получение роли по заданному id"""
    role = role_service.get_role_by_id(id)
    if not role:
        raise abort(HTTPStatus.BAD_REQUEST)
    return role


@auth_app.route("/roles/<id>", methods=["PUT"])
@api.validate(
    json=RolesData, resp=Response("HTTP_400", HTTP_200=RolesData), tags=["Role"]
)
@jwt_required()
@for_admins()
def update_role_by_id(id: uuid):
    """Обновление роли по заданному id"""
    role_data = RolesData(**request.json)
    role = role_service.update_role_by_id(id, role_data)
    if not role:
        raise abort(HTTPStatus.BAD_REQUEST)
    return role


@auth_app.route("/roles", methods=["POST"])
@api.validate(json=RolesData, resp=Response("HTTP_400"), tags=["Role"])
@jwt_required()
@for_admins()
def add_role() -> dict:
    """Создание новой роли"""
    role_data = RolesData(**request.json)
    result = role_service.add_role(role_data)
    if not result:
        raise abort(HTTPStatus.BAD_REQUEST)
    return result


@auth_app.route("/roles/<id>", methods=["DELETE"])
@api.validate(json=RolesData, resp=Response("HTTP_400"), tags=["Role"])
@jwt_required()
@for_admins()
def delete_role(id: uuid) -> dict:
    """Удаление роли по заданному id"""
    result = role_service.delete_role_by_id(id)
    if not result:
        raise abort(HTTPStatus.BAD_REQUEST)
    return result


@auth_app.route("/users/<id>", methods=["DELETE"])
@api.validate(json=UserData, resp=Response("HTTP_400"), tags=["User Management"])
@jwt_required()
@for_admins()
def delete_user_role_by_id(id: uuid):
    """Удаление роли пользователя по id"""
    result = role_service.delete_user_role_by_id(id)
    if not result:
        raise abort(HTTPStatus.BAD_REQUEST)
    return result


@auth_app.route("/users/<user_id>", methods=["PUT"])
@api.validate(json=UserRoleData, resp=Response("HTTP_400"), tags=["User Management"])
@jwt_required()
@for_admins()
def update_user_role_by_id(user_id: uuid):
    """Обновление роли пользователя по id"""
    role_data = UserRoleData(**request.json)
    result = role_service.update_user_role_by_id(user_id, role_data)
    if not result:
        raise abort(HTTPStatus.BAD_REQUEST)
    return result


@auth_app.errorhandler(400)
def handle_400_error(_error) -> Response:
    """Return a http 400 error to client"""
    return make_response(jsonify({"error": "Bad request"}), 400)


@auth_app.errorhandler(HTTPStatus.UNAUTHORIZED)
def handle_401_error(_error) -> Response:
    """Return a http 401 error to client"""
    return make_response(jsonify({"error": "Unauthorised"}), 401)


@auth_app.errorhandler(HTTPStatus.FORBIDDEN)
def handle_403_error(_error) -> Response:
    """Return a http 403 error to client"""
    return make_response(jsonify({"error": "Forbidden"}), 403)


@auth_app.errorhandler(404)
def handle_404_error(_error) -> Response:
    """Return a http 404 error to client"""
    return make_response(jsonify({"error": "Not found"}), 404)


@auth_app.errorhandler(HTTPStatus.CONFLICT)
def handle_409_error(_error) -> Response:
    """Return a http 409 error to client"""
    return make_response(jsonify({"error": "User already exists"}), 409)


@auth_app.errorhandler(PermissionError)
def handle_permission_error(_error) -> Response:
    """Return a http 403 error to client"""
    return make_response(jsonify({"error": "Permission error"}), 403)


@auth_app.errorhandler(500)
def handle_500_error(_error) -> Response:
    """Return a http 500 error to client"""
    return make_response(jsonify({"error": "Server error"}), 500)
