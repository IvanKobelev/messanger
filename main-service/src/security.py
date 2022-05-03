from datetime import datetime, timedelta

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.config import JWT_ACCESS_SECRET, JWT_REFRESH_SECRET
from src.exceptions import UnauthorizedException
from src.schemas import TokenData


http_bearer = HTTPBearer()


def get_access_token_data(token: HTTPAuthorizationCredentials = Depends(http_bearer)) -> TokenData:
    try:
        decoded = jwt.decode(token.credentials, JWT_ACCESS_SECRET, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise UnauthorizedException("Invalid token.")
    except jwt.exceptions.ExpiredSignatureError:
        raise UnauthorizedException("Token has expired.")
    return TokenData.parse_obj(decoded)


def get_refresh_token_data(request: Request) -> TokenData:
    token = request.cookies.get("token")
    try:
        decoded = jwt.decode(token, JWT_REFRESH_SECRET, algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        raise UnauthorizedException("Invalid token.")
    except jwt.exceptions.ExpiredSignatureError:
        raise UnauthorizedException("Token has expired.")
    return TokenData.parse_obj(decoded)


def encode_access_token(data: TokenData):
    payload = data.dict()
    now = datetime.utcnow()
    payload["exp"] = now + timedelta(minutes=15)
    return jwt.encode(payload, JWT_ACCESS_SECRET)


def encode_refresh_token(data: TokenData):
    payload = data.dict()
    now = datetime.utcnow()
    payload["exp"] = now + timedelta(days=15)
    return jwt.encode(payload, JWT_REFRESH_SECRET)
