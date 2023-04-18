import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import UUID

from db.db_init import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    login = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    roles = db.relationship("Role", secondary="user_roles")

    def __repr__(self):
        return f"<User {self.login}>"


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)
    is_superuser = db.Column(db.Boolean, default=False, nullable=False)
    is_privileged = db.Column(db.Boolean, default=False, nullable=False)


class UserRoles(db.Model):
    __tablename__ = "user_roles"
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.UUID(), db.ForeignKey("users.id", ondelete="CASCADE"))
    role_id = db.Column(db.Integer(), db.ForeignKey("roles.id", ondelete="CASCADE"))


class UserHistory(db.Model):
    __tablename__ = "user_history"
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.UUID(), db.ForeignKey("users.id", ondelete="CASCADE"))
    date_logged_in = db.Column(db.DateTime, default=datetime.utcnow)
