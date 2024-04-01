from fastapi import FastAPI, HTTPException
from pymongo import MongoClient
import hashlib
from app.models import UserSignupRequest

app = FastAPI()

client = MongoClient("mongodb://localhost:27017/")
db = client["user_management"]
collection = db["users"]



@app.post("/signup/")
async def signup(user_data: UserSignupRequest):
    if collection.find_one({"$or": [{"username": user_data.username}, {"email": user_data.email}]}):
        raise HTTPException(status_code=400, detail="Username or email already exists")

    hashed_password = hashlib.sha256(user_data.password.encode()).hexdigest()
    user_data.password = hashed_password
    result = collection.insert_one(user_data.dict())
    
    return {"message": "User created successfully", "user_id": str(result.inserted_id)}
