"""URL analysis and reputation checking module."""

import asyncio
import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import aiohttp
from datetime import datetime

from ..integrations.virustotal import VirusTotalClient
from ..integrations.urlvoid import URLVoidClient
from ..utils.database import db_manager

logger = logging.getLogger(__name__)


class URLAnalyzer:
    """Analyzes URLs for phishing and malicious content."""
    
    def __init__(self):
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.zip',
            '.exe', '.scr', '.bat', '.top', '.work', '.party'
        ]
        
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly'
        ]
        
        self.legitimate_domains = [
            'microsoft.com', 'google.com', 'amazon.com', 'paypal.com',
            'apple.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org'
        ]
    
    async def analyze_urls(self, urls: List[str], email_analysis_id: str = None) -> Dict[str, Any]:
        """Analyze a list of URLs for threats."""
        if not urls:
            return {
                'url_count': 0,
                'threat_score': 0.0,
                'malicious_urls': [],
                'suspicious_patterns': [],
                'reputation_results': []
            }
        
        analysis_results = []
        total_threat_score = 0.0
        malicious_count = 0
        
        # Analyze each URL
        for url in urls:
            try:
                url_result = await self._analyze_single_url(url)
                analysis_results.append(url_result)
                
                total_threat_score += url_result['threat_score']
                if url_result['is_malicious']:
                    malicious_count += 1
                
                # Save to database if email_analysis_id provided
                if email_analysis_id:
                    await self._save_url_analysis(email_analysis_id, url_result)
                    
            except Exception as e:
                logger.error(f"Failed to analyze URL {url}: {e}")
                analysis_results.append({
                    'url': url,
                    'threat_score': 0.5,
                    'is_malicious': False,
                    'error': str(e)
                })
        
        # Calculate overall URL threat score
        avg_threat_score = total_threat_score / len(urls) if urls else 0.0
        
        # Extract malicious URLs and patterns
        malicious_urls = [r['url'] for r in analysis_results if r.get('is_malicious')]
        suspicious_patterns = self._extract_suspicious_patterns(analysis_results)
        
        return {
            'url_count': len(urls),
            'threat_score': min(avg_threat_score, 1.0),
            'malicious_count': malicious_count,
            'malicious_urls': malicious_urls,
            'suspicious_patterns': suspicious_patterns,
            'detailed_results': analysis_results,
            'reputation_summary': self._summarize_reputation_results(analysis_results)
        }
    
    async def _analyze_single_url(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL for threats."""
        result = {
            'url': url,
            'domain': '',
            'threat_score': 0.0,
            'is_malicious': False,
            'threat_types': [],
            'analysis_details': {}
        }
        
        try:
            # Parse URL
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            result['domain'] = domain
            
            # Static analysis
            static_score = self._analyze_url_structure(url, parsed)
            result['static_analysis'] = static_score
            
            # Reputation checking
            reputation_tasks = []
            
            # VirusTotal check
            async with VirusTotalClient() as vt_client:
                reputation_tasks.append(vt_client.check_url_reputation(url))
            
            # URLVoid check
            async with URLVoidClient() as uv_client:
                reputation_tasks.append(uv_client.check_url_reputation(url))
            
            # Execute reputation checks in parallel
            reputation_results = await asyncio.gather(*reputation_tasks, return_exceptions=True)
            
            # Process VirusTotal results
            if len(reputation_results) > 0 and not isinstance(reputation_results[0], Exception):
                vt_result = reputation_results[0]
                result['virustotal'] = vt_result
                if vt_result.get('is_malicious'):
                    result['threat_types'].extend(vt_result.get('threat_types', []))
            
            # Process URLVoid results
            if len(reputation_results) > 1 and not isinstance(reputation_results[1], Exception):
                uv_result = reputation_results[1]
                result['urlvoid'] = uv_result
                if uv_result.get('is_malicious'):
                    result['threat_types'].extend(uv_result.get('threat_types', []))
            
            # Calculate combined threat score
            threat_score = self._calculate_combined_threat_score(
                static_score, reputation_results
            )
            
            result['threat_score'] = threat_score
            result['is_malicious'] = threat_score > 0.7
            
            # Deduplicate threat types
            result['threat_types'] = list(set(result['threat_types']))
            
        except Exception as e:
            logger.error(f"URL analysis failed for {url}: {e}")
            result['error'] = str(e)
            result['threat_score'] = 0.5  # Default to medium risk on error
        
        return result
    
    def _analyze_url_structure(self, url: str, parsed) -> Dict[str, Any]:
        """Analyze URL structure for suspicious patterns."""
        analysis = {
            'length_score': 0.0,
            'domain_score': 0.0,
            'path_score': 0.0,
            'parameter_score': 0.0,
            'overall_score': 0.0
        }
        
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # URL length analysis
        if len(url) > 100:
            analysis['length_score'] = 0.3
        if len(url) > 200:
            analysis['length_score'] = 0.6
        if len(url) > 300:
            analysis['length_score'] = 0.9
        
        # Domain analysis
        domain_score = 0.0
        
        # Check for IP addresses
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            domain_score += 0.8
        
        # Check for suspicious TLDs
        if any(tld in url.lower() for tld in self.suspicious_tlds):
            domain_score += 0.6
        
        # Check for URL shorteners
        if any(shortener in domain for shortener in self.url_shorteners):
            domain_score += 0.4
        
        # Check for typosquatting
        typosquatting_score = self._check_typosquatting(domain)
        domain_score += typosquatting_score
        
        # Check for excessive subdomains
        subdomain_count = len(domain.split('.')) - 2
        if subdomain_count > 2:
            domain_score += 0.3
        
        analysis['domain_score'] = min(domain_score, 1.0)
        
        # Path analysis
        path_score = 0.0
        
        # Check for suspicious path patterns
        suspicious_paths = [
            'login', 'signin', 'verify', 'update', 'secure', 'account',
            'banking', 'paypal', 'amazon', 'microsoft', 'google'
        ]
        
        for suspicious_path in suspicious_paths:
            if suspicious_path in path:
                path_score += 0.2
        
        # Check for encoded characters
        if '%' in path and len(re.findall(r'%[0-9a-fA-F]{2}', path)) > 3:
            path_score += 0.4
        
        analysis['path_score'] = min(path_score, 1.0)
        
        # Parameter analysis
        param_score = 0.0
        
        if query:
            params = parse_qs(query)
            
            # Check for suspicious parameters
            suspicious_params = ['redirect', 'url', 'link', 'goto', 'next']
            for param in suspicious_params:
                if param in params:
                    param_score += 0.3
            
            # Check for base64 encoded parameters
            for param_values in params.values():
                for value in param_values:
                    if len(value) > 20 and re.match(r'^[A-Za-z0-9+/]+=*$', value):
                        param_score += 0.4
        
        analysis['parameter_score'] = min(param_score, 1.0)
        
        # Calculate overall structural score
        analysis['overall_score'] = (
            analysis['length_score'] * 0.2 +
            analysis['domain_score'] * 0.4 +
            analysis['path_score'] * 0.3 +
            analysis['parameter_score'] * 0.1
        )
        
        return analysis
    
    def _check_typosquatting(self, domain: str) -> float:
        """Check for typosquatting against legitimate domains."""
        max_similarity = 0.0
        
        for legit_domain in self.legitimate_domains:
            similarity = self._calculate_domain_similarity(domain, legit_domain)
            max_similarity = max(max_similarity, similarity)
        
        # High similarity to legitimate domain but not exact match
        if 0.7 < max_similarity < 1.0:
            return 0.8
        elif 0.5 < max_similarity <= 0.7:
            return 0.4
        
        return 0.0
    
    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between domains using Levenshtein distance."""
        def levenshtein_distance(s1, s2):
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        # Remove TLD for comparison
        domain1_base = domain1.split('.')[0]
        domain2_base = domain2.split('.')[0]
        
        distance = levenshtein_distance(domain1_base, domain2_base)
        max_len = max(len(domain1_base), len(domain2_base))
        
        return 1 - (distance / max_len) if max_len > 0 else 0
    
    def _calculate_combined_threat_score(self, static_analysis: Dict, 
                                       reputation_results: List) -> float:
        """Calculate combined threat score from all analyses."""
        static_score = static_analysis.get('overall_score', 0.0)
        
        # Process reputation scores
        reputation_scores = []
        
        for result in reputation_results:
            if isinstance(result, Exception):
                continue
            
            if isinstance(result, dict):
                rep_score = 1.0 - result.get('reputation_score', 0.5)
                reputation_scores.append(rep_score)
        
        # Calculate weighted average
        if reputation_scores:
            avg_reputation_score = sum(reputation_scores) / len(reputation_scores)
            # Weight: 40% static analysis, 60% reputation
            combined_score = (static_score * 0.4) + (avg_reputation_score * 0.6)
        else:
            # Only static analysis available
            combined_score = static_score
        
        return min(combined_score, 1.0)
    
    def _extract_suspicious_patterns(self, results: List[Dict]) -> List[str]:
        """Extract suspicious patterns from analysis results."""
        patterns = []
        
        for result in results:
            url = result.get('url', '')
            
            # Check for common phishing patterns
            if 'secure' in url.lower() and 'update' in url.lower():
                patterns.append('Fake security update URL')
            
            if any(brand in url.lower() for brand in ['paypal', 'amazon', 'microsoft']):
                if result.get('domain', '') not in self.legitimate_domains:
                    patterns.append('Brand impersonation URL')
            
            if result.get('static_analysis', {}).get('domain_score', 0) > 0.7:
                patterns.append('Suspicious domain structure')
            
            if len(result.get('threat_types', [])) > 2:
                patterns.append('Multiple threat indicators')
        
        return list(set(patterns))
    
    def _summarize_reputation_results(self, results: List[Dict]) -> Dict[str, Any]:
        """Summarize reputation checking results."""
        summary = {
            'total_checked': len(results),
            'malicious_count': 0,
            'clean_count': 0,
            'unknown_count': 0,
            'avg_reputation_score': 0.0
        }
        
        reputation_scores = []
        
        for result in results:
            if result.get('is_malicious'):
                summary['malicious_count'] += 1
            elif result.get('threat_score', 0) < 0.3:
                summary['clean_count'] += 1
            else:
                summary['unknown_count'] += 1
            
            # Collect reputation scores
            if 'virustotal' in result:
                vt_score = result['virustotal'].get('reputation_score', 0.5)
                reputation_scores.append(vt_score)
            
            if 'urlvoid' in result:
                uv_score = result['urlvoid'].get('reputation_score', 0.5)
                reputation_scores.append(uv_score)
        
        if reputation_scores:
            summary['avg_reputation_score'] = sum(reputation_scores) / len(reputation_scores)
        
        return summary
    
    async def _save_url_analysis(self, email_analysis_id: str, url_result: Dict):
        """Save URL analysis results to database."""
        try:
            query = """
            INSERT INTO url_analyses 
            (email_analysis_id, url, domain, virustotal_score, urlvoid_score, 
             is_malicious, threat_types, reputation_category)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """
            
            # Extract scores
            vt_score = None
            uv_score = None
            
            if 'virustotal' in url_result:
                vt_score = 1.0 - url_result['virustotal'].get('reputation_score', 0.5)
            
            if 'urlvoid' in url_result:
                uv_score = 1.0 - url_result['urlvoid'].get('reputation_score', 0.5)
            
            # Determine reputation category
            if url_result.get('is_malicious'):
                reputation_category = 'MALICIOUS'
            elif url_result.get('threat_score', 0) < 0.3:
                reputation_category = 'CLEAN'
            else:
                reputation_category = 'SUSPICIOUS'
            
            await db_manager.execute_command(
                query,
                email_analysis_id,
                url_result['url'],
                url_result.get('domain', ''),
                vt_score,
                uv_score,
                url_result.get('is_malicious', False),
                url_result.get('threat_types', []),
                reputation_category
            )
            
        except Exception as e:
            logger.error(f"Failed to save URL analysis: {e}")
    
    async def get_url_statistics(self) -> Dict[str, Any]:
        """Get URL analysis statistics."""
        try:
            query = """
            SELECT 
                COUNT(*) as total_urls,
                COUNT(*) FILTER (WHERE is_malicious = true) as malicious_urls,
                AVG(virustotal_score) as avg_vt_score,
                AVG(urlvoid_score) as avg_uv_score,
                COUNT(DISTINCT domain) as unique_domains
            FROM url_analyses
            WHERE analyzed_at > NOW() - INTERVAL '30 days'
            """
            
            results = await db_manager.execute_query(query)
            
            if results:
                return results[0]
            else:
                return {
                    'total_urls': 0,
                    'malicious_urls': 0,
                    'avg_vt_score': 0.0,
                    'avg_uv_score': 0.0,
                    'unique_domains': 0
                }
                
        except Exception as e:
            logger.error(f"Failed to get URL statistics: {e}")
            return {}
