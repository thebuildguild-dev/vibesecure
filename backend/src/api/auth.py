from fastapi import APIRouter, Depends, Response, HTTPException, status
from pydantic import BaseModel
from firebase_admin import auth as firebase_auth

from src.auth import get_current_user
from src.auth.provider import _initialize_firebase
from src.core.config import settings


router = APIRouter(prefix="/auth", tags=["auth"])


class UserProfile(BaseModel):
    uid: str
    email: str
    name: str
    email_verified: bool
    picture: str


class LoginRequest(BaseModel):
    firebase_token: str


class LoginResponse(BaseModel):
    success: bool
    message: str


@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, response: Response):
    _initialize_firebase()
    
    try:
        decoded_token = firebase_auth.verify_id_token(request.firebase_token)
        
        response.set_cookie(
            key="vibesecure_token",
            value=request.firebase_token,
            httponly=True,
            secure=not settings.debug, 
            samesite="lax",
            max_age=3600,
            path="/",
        )
        
        return LoginResponse(success=True, message="Login successful")
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Firebase token: {str(e)}",
        )


@router.post("/logout", response_model=LoginResponse)
def logout(response: Response):
    """Clear the session cookie."""
    response.delete_cookie(
        key="vibesecure_token",
        path="/",
        httponly=True,
        secure=not settings.debug,
        samesite="lax",
    )
    
    return LoginResponse(success=True, message="Logout successful")


@router.get("/profile", response_model=UserProfile)
def get_profile(current_user: dict = Depends(get_current_user)):
    return UserProfile(
        uid=current_user["uid"],
        email=current_user["email"],
        name=current_user["name"],
        email_verified=current_user["email_verified"],
        picture=current_user["picture"]
    )
