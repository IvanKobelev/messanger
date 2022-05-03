import hashlib

import jwt
import pytest

from src.config import JWT_ACCESS_SECRET
from src.enums import ServiceUserRole
from src.models import User


@pytest.mark.fixtures({"client": "client"})
def test_health_check_returns_correct_response(fixtures):
    result = fixtures.client.get("/health-check")

    assert result.json() == "Hello, world!"


@pytest.mark.fixtures({"client": "client", "session": "db_empty"})
def test_sign_up_user_returns_correct_response(fixtures):
    json = {
        "login": "login",
        "email": "test@mail.com",
        "password": "password",
        "first_name": "first name",
        "second_name": "second name",
    }

    result = fixtures.client.post("/users/sign-up", json=json)

    assert result.status_code == 200
    result_json = result.json()
    assert result_json["user"]["company_id"] is None
    assert result_json["user"]["company_role"] is None
    assert result_json["user"]["email"] == "test@mail.com"
    assert result_json["user"]["first_name"] == "first name"
    assert result_json["user"]["login"] == "login"
    assert result_json["user"]["second_name"] == "second name"
    assert result_json["user"]["service_role"] == ServiceUserRole.user.value
    token = jwt.decode(result_json["token"], JWT_ACCESS_SECRET, algorithms=["HS256"])
    assert token["id"] == result_json["user"]["id"]
    assert token["company_role"] is None
    assert token["service_role"] == ServiceUserRole.user.value


@pytest.mark.fixtures({"client": "client", "session": "db_empty"})
def test_sign_up_user_creates_in_db_correctly(fixtures):
    json = {
        "login": "login",
        "email": "test@mail.com",
        "password": "password",
        "first_name": "first name",
        "second_name": "second name",
    }

    result = fixtures.client.post("/users/sign-up", json=json)

    assert result.status_code == 200
    user = fixtures.session.query(User).first()
    assert user.company_id is None
    assert user.company_role is None
    assert user.email == "test@mail.com"
    assert user.first_name == "first name"
    assert user.login == "login"
    assert user.password == hashlib.sha256(json["password"].encode()).hexdigest()
    assert user.second_name == "second name"
    assert user.service_role == ServiceUserRole.user


@pytest.mark.fixtures({"client": "client", "session": "db_with_one_user"})
def test_sign_up_user_with_not_unique_fields_returns_400(fixtures):
    json = {
        "login": "login",
        "email": "test@mail.com",
        "password": "password",
        "first_name": "first name",
        "second_name": "second name",
    }

    result = fixtures.client.post("/users/sign-up", json=json)

    assert result.status_code == 400
    assert result.json()["detail"] == "Fields login or email are not unique."
