import os
import json
from typing import Optional
import firebase_admin
from firebase_admin import auth, credentials
from fastapi import HTTPException
from src.core.config import settings


_firebase_initialized = False


def _initialize_firebase() -> None:
    global _firebase_initialized
    
    if _firebase_initialized:
        return
    
    try:
        try:
            firebase_admin.get_app()
            _firebase_initialized = True
            return
        except ValueError:
            pass
        
        if not settings.firebase_credentials_json:
            raise RuntimeError("FIREBASE_CREDENTIALS_JSON environment variable is required")
        
        try:
            cred_dict = json.loads(settings.firebase_credentials_json)
            cred = credentials.Certificate(cred_dict)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid Firebase credentials JSON: {str(e)}")
        
        firebase_admin.initialize_app(cred, {
            'projectId': settings.firebase_project_id,
        })
        
        _firebase_initialized = True
    except Exception as e:
        if "already exists" not in str(e):
            raise RuntimeError(f"Failed to initialize Firebase Admin: {str(e)}")


def verify_google_login(id_token: str) -> dict:
    _initialize_firebase()
    
    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token.get('uid')
        email = decoded_token.get('email')
        name = decoded_token.get('name', '')
        
        if not uid or not email:
            raise HTTPException(
                status_code=401,
                detail="Invalid token: missing required user information"
            )
        
        return {
            "uid": uid,
            "email": email,
            "name": name
        }
        
    except auth.InvalidIdTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid ID token"
        )
    except auth.ExpiredIdTokenError:
        raise HTTPException(
            status_code=401,
            detail="ID token has expired"
        )
    except auth.RevokedIdTokenError:
        raise HTTPException(
            status_code=401,
            detail="ID token has been revoked"
        )
    except auth.CertificateFetchError:
        raise HTTPException(
            status_code=401,
            detail="Error fetching public key certificates"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail=f"Token verification failed: {str(e)}"
        )
