from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UpdatePassword(BaseModel):
    old_password: str
    new_password: str
