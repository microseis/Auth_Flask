#import uuid
from http import HTTPStatus
from flask import (Response, jsonify, make_response, render_template,
                   request, abort, Blueprint)
#from flask_cors import cross_origin
from flask_login import login_required, login_user, logout_user
from src.core.logger import logger
from service.user_service import UserService, get_user_service, UserExistsError, BadLoginError

#from src.db.db_init import db, redis_db
#from src.db.models import Role, User, UserRoles, UserHistory
#from src.core.logger import logger
#from flask_jwt_extended import (
#    create_access_token, create_refresh_token, get_jwt_identity, jwt_required, JWTManager)
#from distutils.util import strtobool
from src.db.helper import RegisterUser

user_service: UserService = get_user_service()

auth_app = Blueprint('auth', __name__)


@auth_app.route("/register", methods=["POST"])
def register_user():
    try:
        user_data = RegisterUser(**request.json)
        logger.info(user_data)
        user_service.register_user(user_data)
        return jsonify({"message": "User has been created"})
    except UserExistsError:
        raise abort(409)
    except BadLoginError:
        raise abort(400)

# @auth_app.route("/roles", methods=["GET"])
# @cross_origin()
# def get_all_roles():
#     roles = Role.query.all()
#     output = []
#     for item in roles:
#         role_data = {"id": item.id,
#                      "name": item.name,
#                      "is_superuser": item.is_superuser,
#                      "is_privileged": item.is_privileged}
#         output.append(role_data)
#
#     return {"roles": output}
#
#
# @auth_app.route("/roles/<id>", methods=["GET"])
# @cross_origin()
# def get_role_by_id(id: uuid):
#     role = Role.query.get_or_404(id)
#     return {"name": role.name, "id": role.id}
#
#
# @auth_app.route("/roles/<id>", methods=["PUT"])
# @cross_origin()
# def update_role_by_id(id: uuid):
#     role = Role.query.get_or_404(id)
#     role.name = request.args.get("role_name")
#     role.is_privileged = strtobool(request.args.get("is_privileged").lower())
#     role.is_superuser = strtobool(request.args.get("is_superuser").lower())
#     db.session.commit()
#     return {
#         "name": role.name,
#         "id": role.id,
#         "is_privileged": role.is_privileged,
#         "is_superuser": role.is_superuser
#     }
#
#
# @auth_app.route("/users/<id>", methods=["PUT"])
# @cross_origin()
# def update_user_role_by_id(id: uuid):
#     logger.info("Requested Role:", request.args.get("role_name"))
#     user_role = UserRoles.query.filter_by(user_id=id).first()
#     if user_role is not None:
#         role = Role.query.filter_by(id=user_role.role_id).first()
#         logger.info("The user has existing role: ", role.name)
#         role_check = Role.query.filter_by(name=request.args.get("role_name")).first()
#         logger.info(role_check)
#         if role_check:
#             logger.info("Proposed role exists in database")
#             user_role.role_id = role_check.id
#             db.session.commit()
#             return {
#                 "user_id": user_role.user_id,
#                 "new_role": request.args.get("role_name"),
#             }
#
#         else:
#             return {"error": "No such role"}
#     else:
#         logger.info("The user has no existing role")
#         role_check = Role.query.filter_by(name=request.args.get("role_name")).first()
#
#         if role_check:
#             logger.info("Proposed role exists in database")
#             new_user_role = UserRoles()
#             new_user_role.role_id = role_check.id
#             new_user_role.user_id = id
#             db.session.add(new_user_role)
#             db.session.commit()
#             return {
#                 "user_id": new_user_role.user_id,
#                 "new_role": request.args.get("role_name"),
#             }
#         else:
#             return {"error": "No such role"}
#
#
# @auth_app.route("/users/<id>", methods=["DELETE"])
# @cross_origin()
# def delete_user_role_by_id(id: uuid):
#     user_role = UserRoles.query.filter_by(user_id=id).first()
#     if user_role is not None:
#         db.session.delete(user_role)
#         db.session.commit()
#         return {"user_id": user_role.user_id, "result": "Role deleted"}
#     else:
#         return {"error": "The user has no any role"}
#
#
# @auth_app.route("/roles", methods=["POST"])
# @cross_origin()
# def add_role() -> dict:
#     if not Role.query.filter(Role.name == request.json["name"]).first():
#         role = Role(
#             name=request.json["name"],
#             is_superuser=request.json["is_superuser"],
#             is_privileged=request.json["is_privileged"]
#         )
#         db.session.add(role)
#         db.session.commit()
#         return {"id": role.id}
#     else:
#         return {"error": " The role already exists"}
#
#
# @auth_app.route("/roles/<id>", methods=["DELETE"])
# @cross_origin()
# def delete_role(id: uuid) -> dict:
#     role = Role.query.get(id)
#     if role is None:
#         return {"error": "No such role"}
#     db.session.delete(role)
#     db.session.commit()
#     return {"message": "Role deleted"}
#
#

#
#
# @auth_app.route("/login", methods=["POST"])
# @cross_origin()
# def loginUser():
#     data = request.get_json()
#     user = User.query.filter(
#         User.login == data.get('login')
#     ).first()
#
#     # if bcrypt.check_password_hash(user.password, data.get('password')):
#     #     login_user(user)
#     #     access_token = create_access_token(identity=user.id, fresh=True)
#     #     refresh_token = create_refresh_token(user.id)
#     #     user_session = UserHistory(user_id=user.id)
#     #     db.session.add(user_session)
#     #     redis_db.set(name=str(user.id), value=refresh_token, ex=3600)
#     #     db.session.commit()
#     #     return {"access_token": access_token, "refresh_token": refresh_token}, 200
#
#     return {"code": 401,
#             "message": "Invalid credentials."}
#
#
# @auth_app.route("/refresh", methods=["POST"])
# @login_required
# @cross_origin()
# @jwt_required(refresh=False)
# def refresh():
#     # We are using the `refresh=True` options in jwt_required to only allow
#     # refresh tokens to access this route.
#     identity = get_jwt_identity()
#     access_token = create_access_token(identity=identity)
#     refresh_token = create_refresh_token(identity)
#     redis_db.set(name=str(identity), value=refresh_token, ex=3600)
#     return make_response(jsonify(access_token=access_token), 200)


@auth_app.route("/user_logout", methods=["POST"])
@login_required
def logoutUser():
    logout_user()
    return {"message": "User has logged out"}


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
def handle_401_error(_error) -> Response:
    """Return a http 409 error to client"""
    return make_response(jsonify({"error": "User already exists"}), 409)

@auth_app.errorhandler(500)
def handle_500_error(_error) -> Response:
    """Return a http 500 error to client"""
    return make_response(jsonify({"error": "Server error"}), 500)
