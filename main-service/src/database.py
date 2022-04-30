import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


SQLALCHEMY_CONNECTION_URL = os.environ.get("SQLALCHEMY_CONNECTION_URL")

engine = create_engine(SQLALCHEMY_CONNECTION_URL)
session = sessionmaker(bind=engine)

Base = declarative_base()


def get_session():
    db = session()
    try:
        yield db
    except Exception as err:
        db.rollback()
        raise err
    finally:
        db.close()
