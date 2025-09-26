"""
FastAPI dependencies for authentication and component injection.
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, Any
import jwt
from ..utils.config import get_settings
from ..core.phishing_detector import PhishingDetector

settings = get_settings()
security = HTTPBearer()

# Global detector instance
_detector_instance = None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """
    Validate JWT token and return current user information.
    """
    try:
        # Decode JWT token
        payload = jwt.decode(
            credentials.credentials,
            settings.JWT_SECRET_KEY,
            algorithms=["HS256"]
        )
        
        user_email = payload.get("sub")
        if user_email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return {
            "email": user_email,
            "name": payload.get("name"),
            "roles": payload.get("roles", [])
        }
        
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_admin_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Ensure current user has admin privileges.
    """
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

async def get_phishing_detector() -> PhishingDetector:
    """
    Get the global phishing detector instance.
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = PhishingDetector()
        await _detector_instance.initialize()
    return _detector_instance
