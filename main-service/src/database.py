from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.scoping import scoped_session

from src.config import SQLALCHEMY_CONNECTION_URL


engine = create_engine(SQLALCHEMY_CONNECTION_URL)
session = scoped_session(sessionmaker(bind=engine))

Base = declarative_base()


def get_session():
    try:
        yield session
    except Exception as err:
        session.rollback()
        raise err
    finally:
        session.remove()
