import sys

from src.core.checker import bcrypt
from src.core.logger import logger
from src.db.db_init import db
from src.db.models import Role, User, UserRoles
from src.main import create_app

app = create_app()
logger.info(sys.argv)
# Подготавливаем контекст и создаём таблицы
app.app_context().push()
db.create_all()

# Создание админа
if len(sys.argv) == 3:
    if not (
        db.session.query(User)
        .filter(User.id == UserRoles.user_id)
        .filter(Role.id == UserRoles.role_id)
        .first()
    ):
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
    logger.info("List of users:")
    for user in all_users:
        logger.info(user.login)

    admins = (
        db.session.query(User)
        .filter(User.id == UserRoles.user_id)
        .filter(Role.id == UserRoles.role_id)
        .all()
    )
    logger.info("List of admins:")
    for admin_user in admins:
        logger.info("Admin: ", admin_user.login)
