from datetime import datetime

from pydantic import BaseModel, validator

from src.enums import CompanyUserRole, ServiceUserRole


class SignUp(BaseModel):

    login: str
    email: str
    password: str
    first_name: str
    second_name: str


class UserOut(BaseModel):

    id: int
    company_id: int | None
    company_role: CompanyUserRole | None
    created_ts: datetime
    email: str
    first_name: str
    login: str
    second_name: str
    service_role: ServiceUserRole

    class Config:
        orm_mode = True


class UserTokenOut(BaseModel):

    user: UserOut
    token: str


class TokenData(BaseModel):

    id: int
    company_role: CompanyUserRole | None
    service_role: ServiceUserRole

    @validator('service_role', 'company_role')
    def return_enum_values(cls, filed):
        if filed is not None:
            return filed.value

    class Config:
        orm_mode = True
