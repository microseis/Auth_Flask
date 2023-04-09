from app import app
from db import db
from db_models import Role, User
from routes import bcrypt

# Подготавливаем контекст и создаём таблицы
app.app_context().push()
db.create_all()

# Создание админа
if not User.query.filter(User.login == "admin").first():
    admin = User(
        login="admin",
        password=bcrypt.generate_password_hash("12345").decode(
            "utf-8",
        ),
    )
    admin.roles.append(Role(name="Admin"))

    db.session.add(admin)
    db.session.commit()

# Select-запросы
all_users = User.query.all()
print("List of users:")
for user in all_users:
    print(user.login)

who_is_admin = User.query.filter_by(login="admin").first()
print("Admin: ", who_is_admin.login)
