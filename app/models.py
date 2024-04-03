from pydantic import BaseModel

class UserSignupRequest(BaseModel):
    username: str
    email: str
    password: str

class UserSigninRequest(BaseModel):
    username_or_email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str