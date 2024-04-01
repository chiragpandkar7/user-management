from pydantic import BaseModel

class UserSignupRequest(BaseModel):
    username: str
    email: str
    password: str