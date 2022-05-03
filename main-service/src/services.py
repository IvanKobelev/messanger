from fastapi import Response
from sqlalchemy.orm import Session

from src import security
from src.models import User
from src.schemas import SignUp, TokenData, UserOut, UserTokenOut


def sign_up_user(user: SignUp, response: Response, session: Session) -> UserTokenOut:
    new_user = User.create(session, user)
    token_data = TokenData.from_orm(new_user)
    access_token = security.encode_access_token(token_data)
    refresh_token = security.encode_refresh_token(token_data)
    response.set_cookie("token", refresh_token, httponly=True)
    return UserTokenOut(user=UserOut.from_orm(new_user), token=access_token)
