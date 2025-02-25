# 🚀 JWT Security Best Practices using FastAPI

from fastapi import FastAPI, Depends, HTTPException, Response, Cookie
from pydantic import BaseModel
from typing import Optional
import jwt
import datetime
import os
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer

# ✅ Load environment variablesr
load_dotenv()
SECRET_KEY = os.getenv("JWT_SECRET") or "supersecurekey"
ALGORITHM = "HS256"

# ✅ FastAPI instance
app = FastAPI()

# ✅ OAuth2 for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ✅ Database Mock (Replace with actual DB in production)
refresh_token_store = {}

# 📌 User Model for Login
class UserLogin(BaseModel):
    user_id: str

# 📌 Generate Access & Refresh Tokens
def generate_tokens(user_id: str):
    access_token = jwt.encode(
        {"sub": user_id, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)},
        SECRET_KEY, algorithm=ALGORITHM
    )
    refresh_token = jwt.encode(
        {"sub": user_id, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)},
        SECRET_KEY, algorithm=ALGORITHM
    )
    refresh_token_store[user_id] = refresh_token  # Store Refresh Token
    return access_token, refresh_token

# 📌 Verify JWT Token
def verify_jwt(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=403, detail="Invalid token")

# 📌 Login Route - Generate Access & Refresh Tokens
@app.post("/login")
def login(user: UserLogin, response: Response):
    access_token, refresh_token = generate_tokens(user.user_id)

    # Store refresh token securely in HttpOnly Secure Cookie
    response.set_cookie(
        key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="Strict"
    )

    return {"access_token": access_token}

# 📌 Protected Route - Requires Valid JWT
@app.get("/protected")
def protected(token: str = Depends(oauth2_scheme)):
    decoded = verify_jwt(token)
    return {"message": "Access granted", "user": decoded["sub"]}

# 📌 Refresh Token Route - Secure Cookie Handling
@app.post("/refresh")
def refresh(refresh_token: Optional[str] = Cookie(None), response: Response = None):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    for user_id, stored_refresh_token in refresh_token_store.items():
        if stored_refresh_token == refresh_token:
            new_access_token, new_refresh_token = generate_tokens(user_id)

            # Store new refresh token in HttpOnly Secure Cookie
            response.set_cookie(
                key="refresh_token", value=new_refresh_token, httponly=True, secure=True, samesite="Strict"
            )

            return {"access_token": new_access_token}

    raise HTTPException(status_code=403, detail="Invalid refresh token")

# 📌 Logout - Clear Refresh Token
@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("refresh_token")
    return {"message": "Successfully logged out"}
