import hashlib
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.scoping import scoped_session

from src.config import SQLALCHEMY_CONNECTION_URL
from src.database import get_session
from src.enums import ServiceUserRole
from src.models import Base, User
from src.views import app


@pytest.fixture
def fixtures(request):
    """Collection of fixtures declared via 'fixtures' mark."""
    fixtures = SimpleNamespace()
    if marker := request.node.get_closest_marker("fixtures"):
        for attr_name, fixture_config in marker.args[0].items():
            fixture = request.getfixturevalue(fixture_config)
            setattr(fixtures, attr_name, fixture)
    return fixtures


@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine(SQLALCHEMY_CONNECTION_URL)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    session = scoped_session(sessionmaker(bind=connection))
    yield session
    transaction.rollback()
    session.remove()
    connection.close()


@pytest.fixture
def db_empty(db_session):
    return db_session


@pytest.fixture
def client(db_empty):
    def override_get_session():
        yield db_empty
    app.dependency_overrides[get_session] = override_get_session
    return TestClient(app)


@pytest.fixture
def db_with_one_user(db_empty):
    session = db_empty
    session.add(User(
        id=1,
        company_id=None,
        company_role=None,
        email="test@mail.com",
        first_name="first name",
        login="login",
        password=hashlib.sha256("password".encode()).hexdigest(),
        second_name="second name",
        service_role=ServiceUserRole.user,
    ))
    session.commit()
    return session
