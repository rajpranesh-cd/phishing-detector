"""
Authentication and authorization utilities.
"""
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from fastapi import HTTPException, status
import secrets

from ..utils.config import get_settings
from ..utils.database import get_db_connection

settings = get_settings()

class AuthManager:
    """
    Handle user authentication and JWT token management.
    """
    
    def __init__(self):
        self.secret_key = settings.JWT_SECRET_KEY
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30
        self.refresh_token_expire_days = 7
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt.
        """
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.
        """
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    
    def create_access_token(self, data: Dict[str, Any]) -> str:
        """
        Create JWT access token.
        """
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        to_encode.update({"exp": expire, "type": "access"})
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """
        Create JWT refresh token.
        """
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        to_encode.update({"exp": expire, "type": "refresh"})
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        """
        Verify and decode JWT token.
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            if payload.get("type") != token_type:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    
    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate user credentials.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_id, email, password_hash, name, roles, is_active
            FROM users 
            WHERE email = %s
        """, (email,))
        
        user = cursor.fetchone()
        conn.close()
        
        if not user or not user[5]:  # Check if user exists and is active
            return None
        
        if not self.verify_password(password, user[2]):
            return None
        
        return {
            "user_id": user[0],
            "email": user[1],
            "name": user[3],
            "roles": user[4] or [],
            "is_active": user[5]
        }
    
    def create_user(self, email: str, password: str, name: str, roles: list = None) -> str:
        """
        Create new user account.
        """
        if roles is None:
            roles = ["user"]
        
        password_hash = self.hash_password(password)
        user_id = secrets.token_urlsafe(16)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO users (user_id, email, password_hash, name, roles, is_active, created_at)
            VALUES (%s, %s, %s, %s, %s, true, NOW())
        """, (user_id, email, password_hash, name, roles))
        
        conn.commit()
        conn.close()
        
        return user_id

class RateLimiter:
    """
    Rate limiting for API endpoints.
    """
    
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.default_limit = 100  # requests per hour
        self.default_window = 3600  # 1 hour in seconds
    
    async def is_allowed(self, key: str, limit: int = None, window: int = None) -> bool:
        """
        Check if request is within rate limit.
        """
        if not self.redis:
            return True  # Allow if Redis not available
        
        limit = limit or self.default_limit
        window = window or self.default_window
        
        try:
            current = await self.redis.get(key)
            
            if current is None:
                await self.redis.setex(key, window, 1)
                return True
            
            if int(current) >= limit:
                return False
            
            await self.redis.incr(key)
            return True
            
        except Exception:
            return True  # Allow on Redis errors
