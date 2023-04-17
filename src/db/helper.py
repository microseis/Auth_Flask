from pydantic import BaseModel, Field


class RegisterUser(BaseModel):
    login: str = Field(min_length=3)
    password: str = Field(min_length=3)
