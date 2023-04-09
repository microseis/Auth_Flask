import uuid

from flask import (Response, jsonify, make_response, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from db import db
from db_models import Role, User, UserRoles
from forms import LoginForm, RegisterForm
from main import app, bcrypt


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if not current_user.is_authenticated:
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(login=form.username.data).first()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for("dashboard"))
        return render_template("login.html", form=form)
    else:
        return redirect("dashboard", code=303)


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    this_user = current_user.login
    return render_template("dashboard.html", user=this_user)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        new_user = User(login=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/roles")
def get_all_roles():
    roles = Role.query.all()
    output = []
    for item in roles:
        role_data = {"id": item.id, "name": item.name}
        output.append(role_data)

    return {"roles": output}


@app.route("/roles/<id>", methods=["GET"])
def get_role_by_id(id: uuid):
    role = Role.query.get_or_404(id)
    return {"name": role.name, "id": role.id}


@app.route("/roles/<id>", methods=["PUT"])
def update_role_by_id(id: uuid):
    role = Role.query.get_or_404(id)
    role.name = request.args.get("role_name")
    db.session.commit()
    return {"name": role.name, "id": role.id}


@app.route("/users/<id>", methods=["PUT"])
def update_user_role_by_id(id: uuid):
    print("Requested Role:", request.args.get("role_name"))
    user_role = UserRoles.query.filter_by(user_id=id).first()
    if user_role is not None:
        role = Role.query.filter_by(id=user_role.role_id).first()
        print("The user has existing role: ", role.name)
        role_check = Role.query.filter_by(name=request.args.get("role_name")).first()
        print(role_check)
        if role_check:
            print("Proposed role exists is database")
            user_role.role_id = role_check.id
            db.session.commit()
            return {
                "user_id": user_role.user_id,
                "new_role": request.args.get("role_name"),
            }

        else:
            return {"error": "No such role"}
    else:
        print("The user has not existing role")
        role_check = Role.query.filter_by(name=request.args.get("role_name")).first()

        if role_check:
            print("Proposed role exists is database")
            new_user_role = UserRoles()
            new_user_role.role_id = role_check.id
            new_user_role.user_id = id
            db.session.add(new_user_role)
            db.session.commit()
            return {
                "user_id": new_user_role.user_id,
                "new_role": request.args.get("role_name"),
            }
        else:
            return {"error": "No such role"}


@app.route("/users/<id>", methods=["DELETE"])
def delete_user_role_by_id(id: uuid):
    user_role = UserRoles.query.filter_by(user_id=id).first()
    if user_role is not None:
        db.session.delete(user_role)
        db.session.commit()
        return {"user_id": user_role.user_id, "result": "Role deleted"}
    else:
        return {"error": "The user has no any role"}


@app.route("/roles", methods=["POST"])
def add_role() -> dict:
    if not Role.query.filter(Role.name == request.json["name"]).first():
        role = Role(name=request.json["name"])
        db.session.add(role)
        db.session.commit()
        return {"id": role.id}
    else:
        return {"error": " The role already exists"}


@app.route("/roles/<id>", methods=["DELETE"])
def delete_role(id: uuid) -> dict:
    role = Role.query.get(id)
    if role is None:
        return {"error": "No such role"}
    db.session.delete(role)
    db.session.commit()
    return {"message": "Role deleted"}


@app.errorhandler(400)
def handle_400_error(_error) -> Response:
    """Return a http 400 error to client"""
    return make_response(jsonify({"error": "Misunderstood"}), 400)


@app.errorhandler(401)
def handle_401_error(_error) -> Response:
    """Return a http 401 error to client"""
    return make_response(jsonify({"error": "Unauthorised"}), 401)


@app.errorhandler(404)
def handle_404_error(_error) -> Response:
    """Return a http 404 error to client"""
    return make_response(jsonify({"error": "Not found"}), 404)


@app.errorhandler(500)
def handle_500_error(_error) -> Response:
    """Return a http 500 error to client"""
    return make_response(jsonify({"error": "Server error"}), 500)
