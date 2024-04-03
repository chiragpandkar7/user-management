from fastapi import Depends, FastAPI, HTTPException
from pymongo import MongoClient
import hashlib
from app.models import UserSigninRequest, UserSignupRequest, Token
from typing import Optional
import jwt
from datetime import datetime, timedelta

app = FastAPI()

client = MongoClient("mongodb://localhost:27017/")
db = client["user_management"]
collection = db["users"]

SECRET_KEY = "31899ef4184dbf80083b37fb6803dc9e21914d00ab3f01ca429129afa6d28be2"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/signup/")
async def signup(user_data: UserSignupRequest):
    if collection.find_one({"$or": [{"username": user_data.username}, {"email": user_data.email}]}):
        raise HTTPException(status_code=400, detail="Username or email already exists")

    hashed_password = hashlib.sha256(user_data.password.encode()).hexdigest()

    user_data.password = hashed_password
    result = collection.insert_one(user_data.dict())
    
    return {"message": "User created successfully", "user_id": str(result.inserted_id)}

@app.post("/signin/", response_model=Token)
async def signin(signin_data: UserSigninRequest):
    user = collection.find_one({"$or": [{"username": signin_data.username_or_email}, {"email": signin_data.username_or_email}]})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    hashed_password = hashlib.sha256(signin_data.password.encode()).hexdigest()
    if hashed_password != user["password"]:
        raise HTTPException(status_code=401, detail="Incorrect password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user["_id"]), "username": user["username"]},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/protected/")
async def protected_route(token: str = Depends(decode_access_token)):
    user_id = token.get("sub")
    return {"user_id": user_id, "message": "This is a protected route"}
