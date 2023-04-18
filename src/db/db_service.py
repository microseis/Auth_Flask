from src.core.logger import logger
from src.db.db_init import db


class DbService:
    @staticmethod
    def add(instance: db.Model) -> str:
        try:
            db.session.add(instance)
            db.session.commit()
            return "User created"
        except Exception as e:
            logger.info(e)
