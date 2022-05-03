from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from src import services
from src.database import get_session
from src.exceptions import BadRequestException, NotFoundException, UnauthorizedException
from src.schemas import SignIn, SignUp, TokenData, UserOut, UserTokenOut
from src.security import get_access_token_data


app = FastAPI()


@app.exception_handler(BadRequestException)
def bad_request_exception(request: Request, exc: BadRequestException) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": exc.message})


@app.exception_handler(UnauthorizedException)
def unauthorized_exception(request: Request, exc: UnauthorizedException) -> JSONResponse:
    return JSONResponse(status_code=401, content={"detail": exc.message})


@app.exception_handler(NotFoundException)
def not_found_exception(request: Request, exc: NotFoundException) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": exc.message})


@app.get("/health-check")
def health_check():
    """Health check main-service."""
    return "Hello, world!"


@app.get("/refresh", response_model=UserTokenOut)
def refresh_tokens(request: Request, response: Response, session: Session = Depends(get_session)) -> UserTokenOut:
    return services.refresh_tokens(request, response, session)


@app.get("/users/profile", response_model=UserOut)
def get_user_profile(
    token_data: TokenData = Depends(get_access_token_data),
    session: Session = Depends(get_session),
) -> UserOut:
    return services.get_user_profile(token_data, session)


@app.post("/users/sign-up", response_model=UserTokenOut)
def sign_up_user(user_data: SignUp, response: Response, session: Session = Depends(get_session)) -> UserTokenOut:
    return services.sign_up_user(user_data, response, session)


@app.post("/users/sign-in", response_model=UserTokenOut)
def sign_in_user(user_data: SignIn, response: Response, session: Session = Depends(get_session)) -> UserTokenOut:
    return services.sign_in_user(user_data, response, session)


@app.get("/users/sign-out")
def sign_out_user(response: Response) -> None:
    return services.sign_out_user(response)
