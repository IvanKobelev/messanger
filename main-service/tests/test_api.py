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


@pytest.mark.fixtures({"client": "client", "session": "db_with_one_user"})
def test_sign_in_user_returns_correct_response(fixtures):
    json = {
        "login": "login",
        "password": "password",
    }

    result = fixtures.client.post("/users/sign-in", json=json)

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


@pytest.mark.fixtures({"client": "client", "session": "db_with_one_user"})
def test_sign_in_user_incorrect_password_returns_401(fixtures):
    json = {
        "login": "login",
        "password": "password_",
    }

    result = fixtures.client.post("/users/sign-in", json=json)

    assert result.status_code == 401
    assert result.json()["detail"] == "Incorrect password."


@pytest.mark.fixtures({"client": "client", "session": "db_with_one_user"})
def test_sign_in_user_user_not_found_returns_404(fixtures):
    json = {
        "login": "login_",
        "password": "password",
    }

    result = fixtures.client.post("/users/sign-in", json=json)

    assert result.status_code == 404
    assert result.json()["detail"] == "User not found."


@pytest.mark.fixtures({"client": "client", "session": "db_with_one_user", "token": "refresh_token"})
def test_refresh_tokens_returns_correct_response(fixtures):
    cookies = {"token": fixtures.token}

    result = fixtures.client.get("/refresh", cookies=cookies)

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


@pytest.mark.fixtures({"client": "client", "session": "db_with_one_user"})
def test_refresh_tokens_without_cookies_returns_401(fixtures):

    result = fixtures.client.get("/refresh")

    assert result.status_code == 401
    assert result.json()["detail"] == "Invalid token."


@pytest.mark.fixtures({"client": "client", "session": "db_with_one_user", "token": "expired_refresh_token"})
def test_refresh_tokens_with_expired_token_returns_401(fixtures):
    cookies = {"token": fixtures.token}

    result = fixtures.client.get("/refresh", cookies=cookies)

    assert result.status_code == 401
    assert result.json()["detail"] == "Token has expired."


@pytest.mark.fixtures({"client": "client", "token": "refresh_token"})
def test_refresh_tokens_user_not_found_returns_404(fixtures):
    cookies = {"token": fixtures.token}

    result = fixtures.client.get("/refresh", cookies=cookies)

    assert result.status_code == 404
    assert result.json()["detail"] == "User not found."


@pytest.mark.fixtures({"client": "client", "session": "db_with_one_user", "token": "access_token"})
def test_get_user_profile_returns_correct_response(fixtures):
    headers = {"Authorization": f"Bearer {fixtures.token}"}

    result = fixtures.client.get("/profile", headers=headers)

    assert result.status_code == 200
    result_json = result.json()
    assert result_json["company_id"] is None
    assert result_json["company_role"] is None
    assert result_json["email"] == "test@mail.com"
    assert result_json["first_name"] == "first name"
    assert result_json["login"] == "login"
    assert result_json["second_name"] == "second name"
    assert result_json["service_role"] == ServiceUserRole.user.value


@pytest.mark.fixtures({"client": "client", "session": "db_with_one_user", "token": "expired_access_token"})
def test_get_user_profile_with_expired_token_returns_401(fixtures):
    headers = {"Authorization": f"Bearer {fixtures.token}"}

    result = fixtures.client.get("/profile", headers=headers)

    assert result.status_code == 401
    assert result.json()["detail"] == "Token has expired."


@pytest.mark.fixtures({"client": "client", "session": "db_with_one_user"})
def test_get_user_profile_without_token_returns_403(fixtures):

    result = fixtures.client.get("/profile")

    assert result.status_code == 403
    assert result.json()["detail"] == "Not authenticated"


@pytest.mark.fixtures({"client": "client", "session": "db_with_one_user", "token": "access_token"})
def test_get_user_profile_with_invalid_token_returns_401(fixtures):
    headers = {"Authorization": f"Bearer {fixtures.token + 'a'}"}

    result = fixtures.client.get("/profile", headers=headers)

    assert result.status_code == 401
    assert result.json()["detail"] == "Invalid token."
