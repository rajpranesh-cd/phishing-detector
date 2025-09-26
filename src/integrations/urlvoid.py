"""URLVoid API integration for additional URL reputation checking."""

import asyncio
import logging
from typing import Dict, Optional
import aiohttp
from urllib.parse import urlparse

from ..utils.config import settings

logger = logging.getLogger(__name__)


class URLVoidClient:
    """URLVoid API client for URL reputation checking."""
    
    def __init__(self):
        self.api_key = settings.urlvoid_api_key
        self.base_url = "https://api.urlvoid.com/v1"
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def check_url_reputation(self, url: str) -> Dict[str, any]:
        """Check URL reputation with URLVoid."""
        if not self.api_key:
            logger.warning("URLVoid API key not configured")
            return {
                "reputation_score": 0.5,
                "is_malicious": False,
                "detections": 0,
                "engines_count": 0,
                "error": "API key not configured"
            }
        
        # Extract domain from URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path
        
        api_url = f"{self.base_url}/pay-as-you-go/"
        params = {
            "key": self.api_key,
            "host": domain
        }
        
        try:
            async with self.session.get(api_url, params=params) as response:
                if response.status == 200:
                    result = await response.json()
                    return self._parse_urlvoid_response(result)
                else:
                    logger.error(f"URLVoid API error: {response.status}")
                    return {
                        "reputation_score": 0.5,
                        "is_malicious": False,
                        "detections": 0,
                        "engines_count": 0,
                        "error": f"API error: {response.status}"
                    }
                    
        except Exception as e:
            logger.error(f"URLVoid request error: {e}")
            return {
                "reputation_score": 0.5,
                "is_malicious": False,
                "detections": 0,
                "engines_count": 0,
                "error": str(e)
            }
    
    def _parse_urlvoid_response(self, result: Dict) -> Dict[str, any]:
        """Parse URLVoid API response."""
        detections = result.get("detections", {})
        engines = detections.get("engines", {})
        
        detection_count = detections.get("count", 0)
        engines_count = len(engines)
        
        # Calculate reputation score (higher is better)
        if engines_count > 0:
            reputation_score = 1.0 - (detection_count / engines_count)
        else:
            reputation_score = 0.5
        
        is_malicious = detection_count > 0
        
        # Extract threat categories
        threat_types = []
        for engine_name, engine_data in engines.items():
            if isinstance(engine_data, dict) and engine_data.get("detected"):
                category = engine_data.get("category", "malicious")
                if category not in threat_types:
                    threat_types.append(category)
        
        return {
            "reputation_score": reputation_score,
            "is_malicious": is_malicious,
            "detections": detection_count,
            "engines_count": engines_count,
            "threat_types": threat_types,
            "engines": engines,
            "domain_info": result.get("domain_info", {}),
            "alexa_rank": result.get("alexa_rank"),
            "domain_age": result.get("domain_age")
        }
