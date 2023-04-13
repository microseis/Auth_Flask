from app import app
from db import db
from db_models import Role, User, UserRoles
from routes import bcrypt
import sys

print(sys.argv)
# Подготавливаем контекст и создаём таблицы
app.app_context().push()
db.create_all()

# Создание админа
if not db.session.query(User).\
    filter(User.id ==UserRoles.user_id).\
    filter(Role.id == UserRoles.role_id).first() and len(sys.argv)==3:
    admin = User(
        login=sys.argv[1],
        password=bcrypt.generate_password_hash(sys.argv[2]).decode(
            "utf-8",
        ),
    )
    admin.roles.append(Role(name="Admin", is_superuser=True))

    db.session.add(admin)
    db.session.commit()

# Select-запросы
all_users = User.query.all()
print("List of users:")
for user in all_users:
    print(user.login)

admins = db.session.query(User).\
    filter(User.id ==UserRoles.user_id).\
    filter(Role.id == UserRoles.role_id).all()
print("List of admins:")
for admin_user in admins:
    print("Admin: ", admin_user.login)
