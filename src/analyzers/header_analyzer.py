"""Email header analysis and forensics module."""

import asyncio
import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
import ipaddress
import socket

from ..utils.database import db_manager

logger = logging.getLogger(__name__)


class HeaderAnalyzer:
    """Analyzes email headers for authentication and routing anomalies."""
    
    def __init__(self):
        self.high_risk_countries = [
            'CN', 'RU', 'NG', 'PK', 'IN', 'BD', 'VN', 'ID', 'PH', 'MY'
        ]
        
        self.suspicious_domains = [
            'tempmail', 'guerrillamail', '10minutemail', 'mailinator',
            'yopmail', 'throwaway', 'temp-mail', 'fakeinbox'
        ]
    
    async def analyze_headers(self, email_data: Dict, email_analysis_id: str = None) -> Dict[str, Any]:
        """Analyze email headers for authentication and routing issues."""
        headers = email_data.get('headers', {})
        internet_headers = email_data.get('internetMessageHeaders', [])
        
        if not headers and not internet_headers:
            return {
                'header_score': 0.5,
                'authentication_score': 0.5,
                'routing_score': 0.5,
                'analysis_details': {},
                'warnings': ['No headers available for analysis']
            }
        
        # Parse headers if they're in internetMessageHeaders format
        if internet_headers and not headers:
            headers = self._parse_internet_headers(internet_headers)
        
        analysis_results = {}
        
        try:
            # Authentication analysis
            auth_analysis = await self._analyze_authentication(headers)
            analysis_results['authentication'] = auth_analysis
            
            # Routing analysis
            routing_analysis = await self._analyze_routing(headers)
            analysis_results['routing'] = routing_analysis
            
            # Timestamp analysis
            timestamp_analysis = self._analyze_timestamps(headers)
            analysis_results['timestamps'] = timestamp_analysis
            
            # Sender analysis
            sender_analysis = await self._analyze_sender(headers)
            analysis_results['sender'] = sender_analysis
            
            # Calculate overall header score
            header_score = self._calculate_header_score(analysis_results)
            
            # Save to database if email_analysis_id provided
            if email_analysis_id:
                await self._save_header_analysis(email_analysis_id, analysis_results, header_score)
            
            return {
                'header_score': header_score,
                'authentication_score': auth_analysis.get('overall_score', 0.5),
                'routing_score': routing_analysis.get('overall_score', 0.5),
                'analysis_details': analysis_results,
                'warnings': self._extract_warnings(analysis_results)
            }
            
        except Exception as e:
            logger.error(f"Header analysis failed: {e}")
            return {
                'header_score': 0.5,
                'authentication_score': 0.5,
                'routing_score': 0.5,
                'analysis_details': {},
                'error': str(e)
            }
    
    def _parse_internet_headers(self, internet_headers: List[Dict]) -> Dict[str, str]:
        """Parse internetMessageHeaders into a dictionary."""
        headers = {}
        
        for header in internet_headers:
            name = header.get('name', '').lower()
            value = header.get('value', '')
            
            if name and value:
                headers[name] = value
        
        return headers
    
    async def _analyze_authentication(self, headers: Dict) -> Dict[str, Any]:
        """Analyze email authentication (SPF, DKIM, DMARC)."""
        analysis = {
            'spf_result': 'none',
            'dkim_result': 'none',
            'dmarc_result': 'none',
            'spf_score': 0.5,
            'dkim_score': 0.5,
            'dmarc_score': 0.5,
            'overall_score': 0.5
        }
        
        # SPF Analysis
        spf_header = headers.get('received-spf', '').lower()
        if 'pass' in spf_header:
            analysis['spf_result'] = 'pass'
            analysis['spf_score'] = 0.0
        elif 'fail' in spf_header:
            analysis['spf_result'] = 'fail'
            analysis['spf_score'] = 1.0
        elif 'softfail' in spf_header:
            analysis['spf_result'] = 'softfail'
            analysis['spf_score'] = 0.7
        elif 'neutral' in spf_header:
            analysis['spf_result'] = 'neutral'
            analysis['spf_score'] = 0.3
        
        # DKIM Analysis
        dkim_signature = headers.get('dkim-signature', '')
        auth_results = headers.get('authentication-results', '').lower()
        
        if dkim_signature:
            if 'dkim=pass' in auth_results:
                analysis['dkim_result'] = 'pass'
                analysis['dkim_score'] = 0.0
            elif 'dkim=fail' in auth_results:
                analysis['dkim_result'] = 'fail'
                analysis['dkim_score'] = 0.8
            else:
                analysis['dkim_result'] = 'present'
                analysis['dkim_score'] = 0.2
        
        # DMARC Analysis
        if 'dmarc=pass' in auth_results:
            analysis['dmarc_result'] = 'pass'
            analysis['dmarc_score'] = 0.0
        elif 'dmarc=fail' in auth_results:
            analysis['dmarc_result'] = 'fail'
            analysis['dmarc_score'] = 0.9
        elif 'dmarc=quarantine' in auth_results:
            analysis['dmarc_result'] = 'quarantine'
            analysis['dmarc_score'] = 0.6
        elif 'dmarc=reject' in auth_results:
            analysis['dmarc_result'] = 'reject'
            analysis['dmarc_score'] = 1.0
        
        # Calculate overall authentication score
        analysis['overall_score'] = (
            analysis['spf_score'] * 0.3 +
            analysis['dkim_score'] * 0.3 +
            analysis['dmarc_score'] * 0.4
        )
        
        return analysis
    
    async def _analyze_routing(self, headers: Dict) -> Dict[str, Any]:
        """Analyze email routing path for anomalies."""
        analysis = {
            'hop_count': 0,
            'suspicious_hops': [],
            'ip_addresses': [],
            'countries': [],
            'routing_score': 0.0,
            'overall_score': 0.0
        }
        
        # Extract Received headers
        received_headers = []
        for key, value in headers.items():
            if key.lower().startswith('received'):
                received_headers.append(value)
        
        analysis['hop_count'] = len(received_headers)
        
        # Analyze each hop
        suspicious_score = 0.0
        
        for received in received_headers:
            # Extract IP addresses
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', received)
            for ip in ip_matches:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not ip_obj.is_private:
                        analysis['ip_addresses'].append(ip)
                        
                        # Get country for IP (simplified - in production use GeoIP)
                        country = await self._get_ip_country(ip)
                        if country:
                            analysis['countries'].append(country)
                            
                            # Check for high-risk countries
                            if country in self.high_risk_countries:
                                suspicious_score += 0.3
                                analysis['suspicious_hops'].append({
                                    'ip': ip,
                                    'country': country,
                                    'reason': 'High-risk country'
                                })
                except ValueError:
                    continue
            
            # Check for suspicious patterns in received headers
            received_lower = received.lower()
            
            # Check for suspicious hostnames
            if any(domain in received_lower for domain in self.suspicious_domains):
                suspicious_score += 0.4
                analysis['suspicious_hops'].append({
                    'header': received[:100],
                    'reason': 'Suspicious domain in routing'
                })
            
            # Check for unusual routing patterns
            if 'unknown' in received_lower or 'localhost' in received_lower:
                suspicious_score += 0.2
        
        # Routing anomaly checks
        if analysis['hop_count'] > 10:
            suspicious_score += 0.3  # Too many hops
        elif analysis['hop_count'] < 2:
            suspicious_score += 0.4  # Too few hops (suspicious)
        
        # Check for country hopping
        unique_countries = list(set(analysis['countries']))
        if len(unique_countries) > 3:
            suspicious_score += 0.3
            analysis['suspicious_hops'].append({
                'reason': f'Multiple countries in routing: {unique_countries}'
            })
        
        analysis['routing_score'] = min(suspicious_score, 1.0)
        analysis['overall_score'] = analysis['routing_score']
        
        return analysis
    
    def _analyze_timestamps(self, headers: Dict) -> Dict[str, Any]:
        """Analyze timestamps for anomalies."""
        analysis = {
            'timestamp_anomalies': False,
            'time_differences': [],
            'timezone_inconsistencies': False,
            'timestamp_score': 0.0
        }
        
        timestamps = []
        
        # Extract timestamps from various headers
        date_header = headers.get('date', '')
        if date_header:
            try:
                date_obj = parsedate_to_datetime(date_header)
                timestamps.append(('date', date_obj))
            except:
                pass
        
        # Extract from Received headers
        received_headers = []
        for key, value in headers.items():
            if key.lower().startswith('received'):
                # Extract timestamp from received header
                timestamp_match = re.search(r';\s*(.+)$', value)
                if timestamp_match:
                    try:
                        timestamp_str = timestamp_match.group(1).strip()
                        timestamp_obj = parsedate_to_datetime(timestamp_str)
                        timestamps.append(('received', timestamp_obj))
                    except:
                        continue
        
        if len(timestamps) < 2:
            return analysis
        
        # Sort timestamps
        timestamps.sort(key=lambda x: x[1])
        
        # Check for anomalies
        suspicious_score = 0.0
        
        for i in range(1, len(timestamps)):
            prev_time = timestamps[i-1][1]
            curr_time = timestamps[i][1]
            
            time_diff = (curr_time - prev_time).total_seconds()
            analysis['time_differences'].append(time_diff)
            
            # Check for negative time differences (emails going back in time)
            if time_diff < 0:
                analysis['timestamp_anomalies'] = True
                suspicious_score += 0.6
            
            # Check for unusually large time gaps (>24 hours)
            elif time_diff > 86400:  # 24 hours
                suspicious_score += 0.3
            
            # Check for timezone inconsistencies
            if prev_time.tzinfo != curr_time.tzinfo:
                analysis['timezone_inconsistencies'] = True
                suspicious_score += 0.2
        
        # Check if email is from the future (>1 hour ahead)
        now = datetime.now(timestamps[0][1].tzinfo) if timestamps[0][1].tzinfo else datetime.now()
        if timestamps[0][1] > now + timedelta(hours=1):
            suspicious_score += 0.4
        
        analysis['timestamp_score'] = min(suspicious_score, 1.0)
        
        return analysis
    
    async def _analyze_sender(self, headers: Dict) -> Dict[str, Any]:
        """Analyze sender information for anomalies."""
        analysis = {
            'sender_ip': None,
            'sender_country': None,
            'sender_reputation': 0.5,
            'return_path_mismatch': False,
            'sender_score': 0.0
        }
        
        # Extract sender IP from first Received header
        received_headers = []
        for key, value in headers.items():
            if key.lower().startswith('received'):
                received_headers.append(value)
        
        if received_headers:
            # Get the first external IP from received headers
            for received in received_headers:
                ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', received)
                for ip in ip_matches:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if not ip_obj.is_private:
                            analysis['sender_ip'] = ip
                            analysis['sender_country'] = await self._get_ip_country(ip)
                            break
                    except ValueError:
                        continue
                if analysis['sender_ip']:
                    break
        
        # Check Return-Path vs From header mismatch
        return_path = headers.get('return-path', '').strip('<>')
        from_header = headers.get('from', '')
        
        if return_path and from_header:
            # Extract email from From header
            from_email_match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
            if from_email_match:
                from_email = from_email_match.group()
                if return_path.lower() != from_email.lower():
                    analysis['return_path_mismatch'] = True
        
        # Calculate sender score
        suspicious_score = 0.0
        
        if analysis['sender_country'] in self.high_risk_countries:
            suspicious_score += 0.4
        
        if analysis['return_path_mismatch']:
            suspicious_score += 0.3
        
        # Check for suspicious sender patterns
        if from_header:
            from_lower = from_header.lower()
            if any(domain in from_lower for domain in self.suspicious_domains):
                suspicious_score += 0.5
        
        analysis['sender_score'] = min(suspicious_score, 1.0)
        
        return analysis
    
    async def _get_ip_country(self, ip: str) -> Optional[str]:
        """Get country code for IP address (simplified implementation)."""
        # In production, use a proper GeoIP service like MaxMind
        # This is a placeholder implementation
        try:
            # Simple mapping for demonstration
            ip_country_map = {
                '8.8.8.8': 'US',
                '1.1.1.1': 'US',
                '208.67.222.222': 'US'
            }
            
            return ip_country_map.get(ip, 'XX')  # XX for unknown
            
        except Exception:
            return None
    
    def _calculate_header_score(self, analysis_results: Dict) -> float:
        """Calculate overall header threat score."""
        auth_score = analysis_results.get('authentication', {}).get('overall_score', 0.5)
        routing_score = analysis_results.get('routing', {}).get('overall_score', 0.5)
        timestamp_score = analysis_results.get('timestamps', {}).get('timestamp_score', 0.0)
        sender_score = analysis_results.get('sender', {}).get('sender_score', 0.0)
        
        # Weighted average
        overall_score = (
            auth_score * 0.4 +
            routing_score * 0.3 +
            timestamp_score * 0.2 +
            sender_score * 0.1
        )
        
        return min(overall_score, 1.0)
    
    def _extract_warnings(self, analysis_results: Dict) -> List[str]:
        """Extract warnings from analysis results."""
        warnings = []
        
        # Authentication warnings
        auth = analysis_results.get('authentication', {})
        if auth.get('spf_result') == 'fail':
            warnings.append('SPF authentication failed')
        if auth.get('dkim_result') == 'fail':
            warnings.append('DKIM signature verification failed')
        if auth.get('dmarc_result') == 'fail':
            warnings.append('DMARC policy violation')
        
        # Routing warnings
        routing = analysis_results.get('routing', {})
        if routing.get('suspicious_hops'):
            warnings.append(f"Suspicious routing detected ({len(routing['suspicious_hops'])} anomalies)")
        
        # Timestamp warnings
        timestamps = analysis_results.get('timestamps', {})
        if timestamps.get('timestamp_anomalies'):
            warnings.append('Timestamp anomalies detected')
        
        # Sender warnings
        sender = analysis_results.get('sender', {})
        if sender.get('return_path_mismatch'):
            warnings.append('Return-Path and From header mismatch')
        if sender.get('sender_country') in self.high_risk_countries:
            warnings.append(f"Email originated from high-risk country: {sender['sender_country']}")
        
        return warnings
    
    async def _save_header_analysis(self, email_analysis_id: str, analysis_results: Dict, header_score: float):
        """Save header analysis results to database."""
        try:
            auth = analysis_results.get('authentication', {})
            routing = analysis_results.get('routing', {})
            sender = analysis_results.get('sender', {})
            timestamps = analysis_results.get('timestamps', {})
            
            query = """
            INSERT INTO header_analyses 
            (email_analysis_id, spf_result, dkim_result, dmarc_result,
             sender_ip, sender_country, sender_reputation_score,
             hop_count, suspicious_routing, timestamp_anomalies, header_authenticity_score)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            """
            
            await db_manager.execute_command(
                query,
                email_analysis_id,
                auth.get('spf_result', 'none'),
                auth.get('dkim_result', 'none'),
                auth.get('dmarc_result', 'none'),
                sender.get('sender_ip'),
                sender.get('sender_country'),
                sender.get('sender_reputation', 0.5),
                routing.get('hop_count', 0),
                len(routing.get('suspicious_hops', [])) > 0,
                timestamps.get('timestamp_anomalies', False),
                header_score
            )
            
        except Exception as e:
            logger.error(f"Failed to save header analysis: {e}")
    
    async def get_header_statistics(self) -> Dict[str, Any]:
        """Get header analysis statistics."""
        try:
            query = """
            SELECT 
                COUNT(*) as total_analyses,
                COUNT(*) FILTER (WHERE spf_result = 'pass') as spf_pass_count,
                COUNT(*) FILTER (WHERE dkim_result = 'pass') as dkim_pass_count,
                COUNT(*) FILTER (WHERE dmarc_result = 'pass') as dmarc_pass_count,
                COUNT(*) FILTER (WHERE suspicious_routing = true) as suspicious_routing_count,
                COUNT(*) FILTER (WHERE timestamp_anomalies = true) as timestamp_anomaly_count,
                AVG(header_authenticity_score) as avg_header_score
            FROM header_analyses
            WHERE analyzed_at > NOW() - INTERVAL '30 days'
            """
            
            results = await db_manager.execute_query(query)
            
            if results:
                return results[0]
            else:
                return {
                    'total_analyses': 0,
                    'spf_pass_count': 0,
                    'dkim_pass_count': 0,
                    'dmarc_pass_count': 0,
                    'suspicious_routing_count': 0,
                    'timestamp_anomaly_count': 0,
                    'avg_header_score': 0.0
                }
                
        except Exception as e:
            logger.error(f"Failed to get header statistics: {e}")
            return {}
