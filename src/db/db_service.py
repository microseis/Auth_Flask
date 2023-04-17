from sqlalchemy.exc import IntegrityError

from src.db.db_init import db


class DbService:

    @staticmethod
    def add(instance: db.Model) -> None:
        db.session.add(instance)
        db.session.commit()
