"""
Security middleware for FastAPI application.
"""
from fastapi import Request, HTTPException, status
from fastapi.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import time
import logging
from typing import Dict, Any
import redis

from .auth import RateLimiter
from .audit import audit_logger, AuditEventType

logger = logging.getLogger(__name__)

class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware for request validation and monitoring.
    """
    
    def __init__(self, app, redis_client=None):
        super().__init__(app)
        self.rate_limiter = RateLimiter(redis_client)
        self.redis = redis_client
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Get client info
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        
        try:
            # Rate limiting
            if not await self._check_rate_limit(request, client_ip):
                audit_logger.log_event(
                    AuditEventType.SECURITY_ALERT,
                    action="rate_limit_exceeded",
                    ip_address=client_ip,
                    user_agent=user_agent,
                    success=False
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded"
                )
            
            # Security headers validation
            self._validate_security_headers(request)
            
            # Process request
            response = await call_next(request)
            
            # Add security headers to response
            self._add_security_headers(response)
            
            # Log successful request
            processing_time = time.time() - start_time
            
            if request.url.path.startswith("/api/"):
                audit_logger.log_event(
                    AuditEventType.API_ACCESS,
                    action=f"{request.method} {request.url.path}",
                    details={
                        "processing_time_ms": round(processing_time * 1000, 2),
                        "status_code": response.status_code
                    },
                    ip_address=client_ip,
                    user_agent=user_agent,
                    success=response.status_code < 400
                )
            
            return response
            
        except HTTPException as e:
            # Log security violations
            audit_logger.log_event(
                AuditEventType.SECURITY_ALERT,
                action="http_exception",
                details={
                    "status_code": e.status_code,
                    "detail": e.detail
                },
                ip_address=client_ip,
                user_agent=user_agent,
                success=False
            )
            raise
        
        except Exception as e:
            # Log unexpected errors
            logger.error(f"Unexpected error in security middleware: {str(e)}")
            audit_logger.log_event(
                AuditEventType.SECURITY_ALERT,
                action="middleware_error",
                details={"error": str(e)},
                ip_address=client_ip,
                user_agent=user_agent,
                success=False
            )
            raise
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Get client IP address from request.
        """
        # Check for forwarded headers (load balancer/proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    async def _check_rate_limit(self, request: Request, client_ip: str) -> bool:
        """
        Check rate limiting for the request.
        """
        # Different limits for different endpoints
        path = request.url.path
        
        if path.startswith("/api/analyze-email"):
            # Stricter limit for analysis endpoints
            return await self.rate_limiter.is_allowed(
                f"analyze:{client_ip}", limit=10, window=3600
            )
        elif path.startswith("/api/"):
            # General API limit
            return await self.rate_limiter.is_allowed(
                f"api:{client_ip}", limit=100, window=3600
            )
        else:
            # Web interface limit
            return await self.rate_limiter.is_allowed(
                f"web:{client_ip}", limit=200, window=3600
            )
    
    def _validate_security_headers(self, request: Request):
        """
        Validate security-related headers.
        """
        # Check for suspicious user agents
        user_agent = request.headers.get("user-agent", "").lower()
        suspicious_agents = ["bot", "crawler", "scanner", "exploit"]
        
        if any(agent in user_agent for agent in suspicious_agents):
            logger.warning(f"Suspicious user agent: {user_agent}")
    
    def _add_security_headers(self, response: Response):
        """
        Add security headers to response.
        """
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self'"
        )

class IPWhitelistMiddleware(BaseHTTPMiddleware):
    """
    IP whitelist middleware for admin endpoints.
    """
    
    def __init__(self, app, whitelist: list = None):
        super().__init__(app)
        self.whitelist = whitelist or []
    
    async def dispatch(self, request: Request, call_next):
        # Only apply to admin endpoints
        if not request.url.path.startswith("/admin/"):
            return await call_next(request)
        
        client_ip = self._get_client_ip(request)
        
        if self.whitelist and client_ip not in self.whitelist:
            audit_logger.log_event(
                AuditEventType.SECURITY_ALERT,
                action="ip_whitelist_violation",
                details={"attempted_path": request.url.path},
                ip_address=client_ip,
                success=False
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        return await call_next(request)
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address."""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
