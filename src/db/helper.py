from pydantic import BaseModel, Field


class RegisterUser(BaseModel):
    login: str = Field(min_length=3)
    password: str = Field(min_length=3)


class LoginUser(RegisterUser):
    pass


class UserTokens(BaseModel):
    access_token: str
    refresh_token: str
