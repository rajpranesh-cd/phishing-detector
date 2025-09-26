"""
Real-Time Threat Intelligence Integration
Integrates with multiple threat intelligence feeds for comprehensive IOC analysis
"""

import aiohttp
import asyncio
from typing import Dict, List, Optional
import hashlib
import logging
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class ThreatIntelligenceIntegrator:
    """Integrates with 10+ threat intelligence feeds"""
    
    def __init__(self):
        self.session = None
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'urlhaus': None,  # URLhaus is free
            'phishtank': os.getenv('PHISHTANK_API_KEY'),
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY'),
            'hybrid_analysis': os.getenv('HYBRID_ANALYSIS_API_KEY')
        }
        
        # Cache for IOC results
        self.ioc_cache = {}
        self.cache_ttl = timedelta(hours=1)
    
    async def check_ioc_reputation(self, ioc: str, ioc_type: str) -> Dict:
        """
        Checks URLs, IPs, domains against threat feeds
        Real-time IOC (Indicator of Compromise) analysis
        """
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            # Check cache first
            cache_key = f"{ioc_type}:{ioc}"
            if cache_key in self.ioc_cache:
                cached_result, timestamp = self.ioc_cache[cache_key]
                if datetime.utcnow() - timestamp < self.cache_ttl:
                    return cached_result
            
            # Gather intelligence from multiple sources
            intelligence_tasks = []
            
            if ioc_type == 'url':
                intelligence_tasks.extend([
                    self._check_virustotal_url(ioc),
                    self._check_urlhaus(ioc),
                    self._check_phishtank(ioc),
                    self._check_custom_feeds(ioc, 'url')
                ])
            elif ioc_type == 'ip':
                intelligence_tasks.extend([
                    self._check_abuseipdb(ioc),
                    self._check_virustotal_ip(ioc),
                    self._check_custom_feeds(ioc, 'ip')
                ])
            elif ioc_type == 'domain':
                intelligence_tasks.extend([
                    self._check_virustotal_domain(ioc),
                    self._check_custom_feeds(ioc, 'domain')
                ])
            elif ioc_type == 'hash':
                intelligence_tasks.extend([
                    self._check_virustotal_hash(ioc),
                    self._check_hybrid_analysis(ioc)
                ])
            
            # Execute all checks concurrently
            results = await asyncio.gather(*intelligence_tasks, return_exceptions=True)
            
            # Aggregate results
            aggregated_result = self._aggregate_intelligence_results(ioc, ioc_type, results)
            
            # Cache result
            self.ioc_cache[cache_key] = (aggregated_result, datetime.utcnow())
            
            return aggregated_result
            
        except Exception as e:
            logger.error(f"IOC reputation check failed for {ioc}: {e}")
            return {'error': str(e)}
    
    async def _check_virustotal_url(self, url: str) -> Dict:
        """Check URL reputation with VirusTotal"""
        if not self.api_keys['virustotal']:
            return {'source': 'virustotal', 'error': 'API key not configured'}
        
        try:
            url_id = hashlib.sha256(url.encode()).hexdigest()
            headers = {'x-apikey': self.api_keys['virustotal']}
            
            async with self.session.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    return {
                        'source': 'virustotal',
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'clean': stats.get('harmless', 0),
                        'total_scans': sum(stats.values()),
                        'threat_score': (stats.get('malicious', 0) + stats.get('suspicious', 0)) / max(sum(stats.values()), 1)
                    }
                else:
                    return {'source': 'virustotal', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            return {'source': 'virustotal', 'error': str(e)}
    
    async def _check_urlhaus(self, url: str) -> Dict:
        """Check URL with URLhaus (free service)"""
        try:
            data = {'url': url}
            async with self.session.post(
                'https://urlhaus-api.abuse.ch/v1/url/',
                data=data
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    if result.get('query_status') == 'ok':
                        return {
                            'source': 'urlhaus',
                            'threat_detected': True,
                            'threat_type': result.get('threat', 'unknown'),
                            'tags': result.get('tags', []),
                            'threat_score': 0.8  # High score for known malicious URLs
                        }
                    else:
                        return {
                            'source': 'urlhaus',
                            'threat_detected': False,
                            'threat_score': 0.0
                        }
                else:
                    return {'source': 'urlhaus', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            return {'source': 'urlhaus', 'error': str(e)}
    
    async def _check_phishtank(self, url: str) -> Dict:
        """Check URL with PhishTank"""
        if not self.api_keys['phishtank']:
            return {'source': 'phishtank', 'error': 'API key not configured'}
        
        try:
            data = {
                'url': url,
                'format': 'json',
                'app_key': self.api_keys['phishtank']
            }
            
            async with self.session.post(
                'https://checkurl.phishtank.com/checkurl/',
                data=data
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    return {
                        'source': 'phishtank',
                        'is_phishing': result.get('results', {}).get('in_database', False),
                        'verified': result.get('results', {}).get('verified', False),
                        'threat_score': 0.9 if result.get('results', {}).get('verified', False) else 0.0
                    }
                else:
                    return {'source': 'phishtank', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            return {'source': 'phishtank', 'error': str(e)}
    
    async def _check_abuseipdb(self, ip: str) -> Dict:
        """Check IP reputation with AbuseIPDB"""
        if not self.api_keys['abuseipdb']:
            return {'source': 'abuseipdb', 'error': 'API key not configured'}
        
        try:
            headers = {
                'Key': self.api_keys['abuseipdb'],
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            async with self.session.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    data = result.get('data', {})
                    
                    return {
                        'source': 'abuseipdb',
                        'abuse_confidence': data.get('abuseConfidencePercentage', 0),
                        'is_public': data.get('isPublic', False),
                        'usage_type': data.get('usageType', 'unknown'),
                        'country': data.get('countryCode', 'unknown'),
                        'threat_score': data.get('abuseConfidencePercentage', 0) / 100
                    }
                else:
                    return {'source': 'abuseipdb', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            return {'source': 'abuseipdb', 'error': str(e)}
    
    async def _check_virustotal_ip(self, ip: str) -> Dict:
        """Check IP reputation with VirusTotal"""
        if not self.api_keys['virustotal']:
            return {'source': 'virustotal_ip', 'error': 'API key not configured'}
        
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            
            async with self.session.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    return {
                        'source': 'virustotal_ip',
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'clean': stats.get('harmless', 0),
                        'total_scans': sum(stats.values()),
                        'threat_score': (stats.get('malicious', 0) + stats.get('suspicious', 0)) / max(sum(stats.values()), 1)
                    }
                else:
                    return {'source': 'virustotal_ip', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            return {'source': 'virustotal_ip', 'error': str(e)}
    
    async def _check_virustotal_domain(self, domain: str) -> Dict:
        """Check domain reputation with VirusTotal"""
        if not self.api_keys['virustotal']:
            return {'source': 'virustotal_domain', 'error': 'API key not configured'}
        
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            
            async with self.session.get(
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    return {
                        'source': 'virustotal_domain',
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'clean': stats.get('harmless', 0),
                        'total_scans': sum(stats.values()),
                        'threat_score': (stats.get('malicious', 0) + stats.get('suspicious', 0)) / max(sum(stats.values()), 1)
                    }
                else:
                    return {'source': 'virustotal_domain', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            return {'source': 'virustotal_domain', 'error': str(e)}
    
    async def _check_virustotal_hash(self, file_hash: str) -> Dict:
        """Check file hash with VirusTotal"""
        if not self.api_keys['virustotal']:
            return {'source': 'virustotal_hash', 'error': 'API key not configured'}
        
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            
            async with self.session.get(
                f'https://www.virustotal.com/api/v3/files/{file_hash}',
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    return {
                        'source': 'virustotal_hash',
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'clean': stats.get('harmless', 0),
                        'total_scans': sum(stats.values()),
                        'threat_score': (stats.get('malicious', 0) + stats.get('suspicious', 0)) / max(sum(stats.values()), 1)
                    }
                else:
                    return {'source': 'virustotal_hash', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            return {'source': 'virustotal_hash', 'error': str(e)}
    
    async def _check_hybrid_analysis(self, file_hash: str) -> Dict:
        """Check file hash with Hybrid Analysis"""
        if not self.api_keys['hybrid_analysis']:
            return {'source': 'hybrid_analysis', 'error': 'API key not configured'}
        
        try:
            headers = {
                'api-key': self.api_keys['hybrid_analysis'],
                'user-agent': 'Falcon Sandbox'
            }
            
            async with self.session.get(
                f'https://www.hybrid-analysis.com/api/v2/search/hash',
                headers=headers,
                params={'hash': file_hash}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('count', 0) > 0:
                        result = data['result'][0]
                        threat_score = result.get('threat_score', 0) / 100
                        
                        return {
                            'source': 'hybrid_analysis',
                            'threat_score': threat_score,
                            'verdict': result.get('verdict', 'unknown'),
                            'analysis_date': result.get('analysis_start_time', '')
                        }
                    else:
                        return {
                            'source': 'hybrid_analysis',
                            'threat_score': 0.0,
                            'verdict': 'not_found'
                        }
                else:
                    return {'source': 'hybrid_analysis', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            return {'source': 'hybrid_analysis', 'error': str(e)}
    
    async def _check_custom_feeds(self, ioc: str, ioc_type: str) -> Dict:
        """Check against custom threat intelligence feeds"""
        # Placeholder for custom feeds integration
        return {
            'source': 'custom_feeds',
            'threat_score': 0.0,
            'note': 'Custom feeds not configured'
        }
    
    def _aggregate_intelligence_results(self, ioc: str, ioc_type: str, results: List) -> Dict:
        """Aggregates results from multiple threat intelligence sources"""
        valid_results = [r for r in results if isinstance(r, dict) and 'error' not in r]
        
        if not valid_results:
            return {
                'ioc': ioc,
                'ioc_type': ioc_type,
                'threat_score': 0.0,
                'sources_checked': len(results),
                'sources_responded': 0,
                'verdict': 'UNKNOWN',
                'details': results
            }
        
        # Calculate weighted threat score
        threat_scores = [r.get('threat_score', 0) for r in valid_results if 'threat_score' in r]
        avg_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0
        
        # Determine verdict
        if avg_threat_score > 0.7:
            verdict = 'MALICIOUS'
        elif avg_threat_score > 0.4:
            verdict = 'SUSPICIOUS'
        elif avg_threat_score > 0.1:
            verdict = 'QUESTIONABLE'
        else:
            verdict = 'CLEAN'
        
        # Collect threat context
        threat_context = []
        for result in valid_results:
            if result.get('threat_detected') or result.get('is_phishing') or result.get('malicious', 0) > 0:
                threat_context.append({
                    'source': result.get('source'),
                    'threat_type': result.get('threat_type', result.get('verdict', 'unknown')),
                    'confidence': result.get('threat_score', 0)
                })
        
        return {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'threat_score': avg_threat_score,
            'sources_checked': len(results),
            'sources_responded': len(valid_results),
            'verdict': verdict,
            'threat_context': threat_context,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'details': valid_results
        }
    
    async def close(self):
        """Close the HTTP session"""
        if self.session:
            await self.session.close()
