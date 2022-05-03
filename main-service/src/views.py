from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from src import services
from src.database import get_session
from src.exceptions import BadRequestException, UnauthorizedException
from src.schemas import SignUp, UserTokenOut


app = FastAPI()


@app.exception_handler(BadRequestException)
def bad_request_exception(request: Request, exc: BadRequestException) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": exc.message})


@app.exception_handler(UnauthorizedException)
def unauthorized_exception(request: Request, exc: UnauthorizedException) -> JSONResponse:
    return JSONResponse(status_code=401, content={"detail": exc.message})


@app.get("/health-check")
def health_check():
    """Health check main-service."""
    return "Hello, world!"


@app.post("/users/sign-up", response_model=UserTokenOut)
def sign_up_user(user: SignUp, response: Response, session: Session = Depends(get_session)) -> UserTokenOut:
    return services.sign_up_user(user, response, session)
