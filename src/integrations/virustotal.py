"""VirusTotal API integration for URL and file reputation checking."""

import asyncio
import logging
from typing import Dict, Optional, List
import aiohttp
import hashlib

from ..utils.config import settings

logger = logging.getLogger(__name__)


class VirusTotalClient:
    """VirusTotal API client for threat intelligence."""
    
    def __init__(self):
        self.api_key = settings.virustotal_api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def _make_request(self, endpoint: str, params: Dict) -> Optional[Dict]:
        """Make request to VirusTotal API."""
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None
        
        params["apikey"] = self.api_key
        url = f"{self.base_url}/{endpoint}"
        
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 204:
                    logger.info("VirusTotal rate limit reached")
                    return None
                else:
                    logger.error(f"VirusTotal API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"VirusTotal request error: {e}")
            return None
    
    async def check_url_reputation(self, url: str) -> Dict[str, any]:
        """Check URL reputation with VirusTotal."""
        params = {
            "resource": url,
            "scan": "1"  # Submit for scanning if not found
        }
        
        result = await self._make_request("url/report", params)
        
        if not result:
            return {
                "reputation_score": 0.0,
                "is_malicious": False,
                "threat_types": [],
                "scan_results": {},
                "error": "API request failed"
            }
        
        # Parse results
        positives = result.get("positives", 0)
        total = result.get("total", 1)
        reputation_score = 1.0 - (positives / total) if total > 0 else 0.5
        
        is_malicious = positives > 0
        threat_types = []
        
        # Extract threat types from scan results
        scans = result.get("scans", {})
        for engine, scan_result in scans.items():
            if scan_result.get("detected"):
                threat_type = scan_result.get("result", "").lower()
                if threat_type and threat_type not in threat_types:
                    threat_types.append(threat_type)
        
        return {
            "reputation_score": reputation_score,
            "is_malicious": is_malicious,
            "threat_types": threat_types,
            "positives": positives,
            "total": total,
            "scan_results": scans,
            "permalink": result.get("permalink"),
            "scan_date": result.get("scan_date")
        }
    
    async def check_file_hash(self, file_hash: str) -> Dict[str, any]:
        """Check file hash reputation."""
        params = {
            "resource": file_hash
        }
        
        result = await self._make_request("file/report", params)
        
        if not result:
            return {
                "reputation_score": 0.5,
                "is_malicious": False,
                "threat_types": [],
                "error": "API request failed"
            }
        
        positives = result.get("positives", 0)
        total = result.get("total", 1)
        reputation_score = 1.0 - (positives / total) if total > 0 else 0.5
        
        is_malicious = positives > 0
        threat_types = []
        
        # Extract malware families
        scans = result.get("scans", {})
        for engine, scan_result in scans.items():
            if scan_result.get("detected"):
                threat_type = scan_result.get("result", "").lower()
                if threat_type and threat_type not in threat_types:
                    threat_types.append(threat_type)
        
        return {
            "reputation_score": reputation_score,
            "is_malicious": is_malicious,
            "threat_types": threat_types,
            "positives": positives,
            "total": total,
            "scan_results": scans,
            "md5": result.get("md5"),
            "sha1": result.get("sha1"),
            "sha256": result.get("sha256")
        }
    
    async def submit_file_for_analysis(self, file_data: bytes, 
                                     filename: str) -> Optional[str]:
        """Submit file for analysis and return scan ID."""
        if not self.api_key:
            return None
        
        url = f"{self.base_url}/file/scan"
        
        data = aiohttp.FormData()
        data.add_field("apikey", self.api_key)
        data.add_field("file", file_data, filename=filename)
        
        try:
            async with self.session.post(url, data=data) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get("scan_id")
                else:
                    logger.error(f"File submission failed: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"File submission error: {e}")
            return None
    
    async def get_scan_report(self, scan_id: str) -> Optional[Dict]:
        """Get scan report by scan ID."""
        params = {
            "resource": scan_id
        }
        
        return await self._make_request("file/report", params)
    
    @staticmethod
    def calculate_file_hash(file_data: bytes, hash_type: str = "sha256") -> str:
        """Calculate file hash."""
        if hash_type == "md5":
            return hashlib.md5(file_data).hexdigest()
        elif hash_type == "sha1":
            return hashlib.sha1(file_data).hexdigest()
        elif hash_type == "sha256":
            return hashlib.sha256(file_data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
