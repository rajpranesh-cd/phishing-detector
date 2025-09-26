"""Attachment analysis and malware detection module."""

import asyncio
import logging
import hashlib
import mimetypes
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import base64

from ..integrations.yara_engine import YaraEngine
from ..integrations.virustotal import VirusTotalClient
from ..utils.database import db_manager

logger = logging.getLogger(__name__)


class AttachmentAnalyzer:
    """Analyzes email attachments for malware and threats."""
    
    def __init__(self):
        self.yara_engine = YaraEngine()
        
        self.suspicious_extensions = {
            '.exe': 0.9, '.scr': 0.9, '.bat': 0.8, '.cmd': 0.8,
            '.pif': 0.9, '.com': 0.8, '.msi': 0.7, '.vbs': 0.8,
            '.js': 0.6, '.jar': 0.7, '.zip': 0.4, '.rar': 0.4,
            '.7z': 0.4, '.ace': 0.5, '.cab': 0.5, '.iso': 0.6,
            '.img': 0.6, '.dmg': 0.5, '.pkg': 0.5, '.deb': 0.4,
            '.rpm': 0.4, '.tar.gz': 0.3, '.tar.bz2': 0.3
        }
        
        self.executable_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.pif', '.com', '.msi',
            '.app', '.deb', '.rpm', '.pkg', '.dmg'
        }
        
        self.document_extensions = {
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.pdf', '.rtf', '.odt', '.ods', '.odp'
        }
        
        # Maximum file size for analysis (50MB)
        self.max_analysis_size = 50 * 1024 * 1024
    
    async def analyze_attachments(self, attachments: List[Dict], 
                                email_analysis_id: str = None) -> Dict[str, Any]:
        """Analyze all attachments in an email."""
        if not attachments:
            return {
                'attachment_count': 0,
                'threat_score': 0.0,
                'malicious_attachments': [],
                'suspicious_files': [],
                'analysis_summary': {}
            }
        
        analysis_results = []
        total_threat_score = 0.0
        malicious_count = 0
        
        # Analyze each attachment
        for attachment in attachments:
            try:
                attachment_result = await self._analyze_single_attachment(attachment)
                analysis_results.append(attachment_result)
                
                total_threat_score += attachment_result['threat_score']
                if attachment_result['is_malware']:
                    malicious_count += 1
                
                # Save to database if email_analysis_id provided
                if email_analysis_id:
                    await self._save_attachment_analysis(email_analysis_id, attachment_result)
                    
            except Exception as e:
                logger.error(f"Failed to analyze attachment {attachment.get('filename', 'unknown')}: {e}")
                analysis_results.append({
                    'filename': attachment.get('filename', 'unknown'),
                    'threat_score': 0.5,
                    'is_malware': False,
                    'error': str(e)
                })
        
        # Calculate overall attachment threat score
        avg_threat_score = total_threat_score / len(attachments) if attachments else 0.0
        
        # Extract malicious and suspicious files
        malicious_files = [r['filename'] for r in analysis_results if r.get('is_malware')]
        suspicious_files = [r['filename'] for r in analysis_results 
                          if r.get('threat_score', 0) > 0.5 and not r.get('is_malware')]
        
        return {
            'attachment_count': len(attachments),
            'threat_score': min(avg_threat_score, 1.0),
            'malicious_count': malicious_count,
            'malicious_attachments': malicious_files,
            'suspicious_files': suspicious_files,
            'detailed_results': analysis_results,
            'analysis_summary': self._summarize_attachment_analysis(analysis_results)
        }
    
    async def _analyze_single_attachment(self, attachment: Dict) -> Dict[str, Any]:
        """Analyze a single attachment for threats."""
        result = {
            'filename': attachment.get('filename', 'unknown'),
            'file_size': attachment.get('file_size', 0),
            'mime_type': attachment.get('mime_type', ''),
            'threat_score': 0.0,
            'is_malware': False,
            'analysis_details': {}
        }
        
        try:
            filename = attachment.get('filename', '')
            file_size = attachment.get('file_size', 0)
            file_data = attachment.get('file_data')  # Base64 encoded or bytes
            
            # Decode file data if base64 encoded
            if isinstance(file_data, str):
                try:
                    file_data = base64.b64decode(file_data)
                except Exception as e:
                    logger.warning(f"Failed to decode attachment data: {e}")
                    file_data = None
            
            # Calculate file hash
            if file_data:
                file_hash = hashlib.sha256(file_data).hexdigest()
                result['file_hash'] = file_hash
            
            # Static analysis
            static_analysis = self._analyze_file_properties(filename, file_size, 
                                                          attachment.get('mime_type', ''))
            result['static_analysis'] = static_analysis
            
            # YARA analysis (if file data available)
            yara_analysis = {}
            if file_data and len(file_data) <= self.max_analysis_size:
                yara_threat_score, yara_matches = self.yara_engine.scan_file(file_data, filename)
                yara_analysis = {
                    'threat_score': yara_threat_score,
                    'matches': yara_matches,
                    'rules_triggered': len(yara_matches)
                }
            result['yara_analysis'] = yara_analysis
            
            # VirusTotal hash check (if hash available)
            vt_analysis = {}
            if result.get('file_hash'):
                try:
                    async with VirusTotalClient() as vt_client:
                        vt_result = await vt_client.check_file_hash(result['file_hash'])
                        vt_analysis = vt_result
                except Exception as e:
                    logger.warning(f"VirusTotal check failed: {e}")
            result['virustotal_analysis'] = vt_analysis
            
            # Calculate combined threat score
            threat_score = self._calculate_attachment_threat_score(
                static_analysis, yara_analysis, vt_analysis
            )
            
            result['threat_score'] = threat_score
            result['is_malware'] = threat_score > 0.7
            
            # Determine malware family if detected
            if result['is_malware']:
                result['malware_family'] = self._determine_malware_family(
                    yara_analysis, vt_analysis
                )
            
        except Exception as e:
            logger.error(f"Attachment analysis failed for {filename}: {e}")
            result['error'] = str(e)
            result['threat_score'] = 0.5  # Default to medium risk on error
        
        return result
    
    def _analyze_file_properties(self, filename: str, file_size: int, 
                               mime_type: str) -> Dict[str, Any]:
        """Analyze file properties for suspicious characteristics."""
        analysis = {
            'extension_score': 0.0,
            'size_score': 0.0,
            'mime_score': 0.0,
            'name_score': 0.0,
            'overall_score': 0.0
        }
        
        filename_lower = filename.lower()
        
        # Extension analysis
        extension_score = 0.0
        file_extension = Path(filename).suffix.lower()
        
        if file_extension in self.suspicious_extensions:
            extension_score = self.suspicious_extensions[file_extension]
        elif file_extension in self.executable_extensions:
            extension_score = 0.8
        
        # Double extension check (e.g., .pdf.exe)
        if filename_lower.count('.') > 1:
            parts = filename_lower.split('.')
            if len(parts) >= 3:
                second_ext = '.' + parts[-2]
                if second_ext in self.document_extensions and file_extension in self.executable_extensions:
                    extension_score = 0.9  # Very suspicious
        
        analysis['extension_score'] = extension_score
        
        # File size analysis
        size_score = 0.0
        if file_size == 0:
            size_score = 0.3  # Empty files are suspicious
        elif file_size < 1024:  # Very small files
            size_score = 0.2
        elif file_size > 100 * 1024 * 1024:  # Very large files (>100MB)
            size_score = 0.4
        
        analysis['size_score'] = size_score
        
        # MIME type analysis
        mime_score = 0.0
        if mime_type:
            # Check for MIME/extension mismatch
            expected_mime = mimetypes.guess_type(filename)[0]
            if expected_mime and expected_mime != mime_type:
                mime_score = 0.6
            
            # Suspicious MIME types
            suspicious_mimes = [
                'application/x-executable',
                'application/x-msdownload',
                'application/x-msdos-program'
            ]
            if mime_type in suspicious_mimes:
                mime_score = 0.8
        
        analysis['mime_score'] = mime_score
        
        # Filename analysis
        name_score = 0.0
        
        # Check for suspicious patterns in filename
        suspicious_patterns = [
            'invoice', 'receipt', 'document', 'photo', 'image',
            'urgent', 'important', 'confidential', 'secure'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in filename_lower and file_extension in self.executable_extensions:
                name_score += 0.3
        
        # Check for random-looking names
        if len(filename) > 20 and sum(c.isdigit() for c in filename) > len(filename) * 0.5:
            name_score += 0.2
        
        analysis['name_score'] = min(name_score, 1.0)
        
        # Calculate overall static score
        analysis['overall_score'] = (
            analysis['extension_score'] * 0.4 +
            analysis['size_score'] * 0.1 +
            analysis['mime_score'] * 0.3 +
            analysis['name_score'] * 0.2
        )
        
        return analysis
    
    def _calculate_attachment_threat_score(self, static_analysis: Dict,
                                         yara_analysis: Dict, vt_analysis: Dict) -> float:
        """Calculate combined threat score for attachment."""
        static_score = static_analysis.get('overall_score', 0.0)
        yara_score = yara_analysis.get('threat_score', 0.0)
        
        # VirusTotal score
        vt_score = 0.0
        if vt_analysis.get('is_malicious'):
            vt_score = 1.0 - vt_analysis.get('reputation_score', 0.5)
        
        # Weight the scores
        if vt_score > 0:
            # If we have VT results, weight them heavily
            combined_score = (static_score * 0.2) + (yara_score * 0.3) + (vt_score * 0.5)
        elif yara_score > 0:
            # If we have YARA results but no VT
            combined_score = (static_score * 0.3) + (yara_score * 0.7)
        else:
            # Only static analysis
            combined_score = static_score
        
        return min(combined_score, 1.0)
    
    def _determine_malware_family(self, yara_analysis: Dict, vt_analysis: Dict) -> str:
        """Determine malware family from analysis results."""
        # Check YARA matches first
        if yara_analysis.get('matches'):
            for match in yara_analysis['matches']:
                category = match.get('category', '').lower()
                if 'trojan' in category:
                    return 'Trojan'
                elif 'ransomware' in category:
                    return 'Ransomware'
                elif 'backdoor' in category:
                    return 'Backdoor'
                elif 'worm' in category:
                    return 'Worm'
        
        # Check VirusTotal results
        if vt_analysis.get('threat_types'):
            threat_types = vt_analysis['threat_types']
            for threat_type in threat_types:
                threat_lower = threat_type.lower()
                if 'trojan' in threat_lower:
                    return 'Trojan'
                elif 'ransomware' in threat_lower or 'crypto' in threat_lower:
                    return 'Ransomware'
                elif 'backdoor' in threat_lower:
                    return 'Backdoor'
                elif 'worm' in threat_lower:
                    return 'Worm'
                elif 'adware' in threat_lower:
                    return 'Adware'
        
        return 'Unknown Malware'
    
    def _summarize_attachment_analysis(self, results: List[Dict]) -> Dict[str, Any]:
        """Summarize attachment analysis results."""
        summary = {
            'total_files': len(results),
            'malware_detected': 0,
            'suspicious_files': 0,
            'clean_files': 0,
            'file_types': {},
            'avg_threat_score': 0.0,
            'yara_detections': 0,
            'vt_detections': 0
        }
        
        threat_scores = []
        
        for result in results:
            threat_score = result.get('threat_score', 0.0)
            threat_scores.append(threat_score)
            
            if result.get('is_malware'):
                summary['malware_detected'] += 1
            elif threat_score > 0.5:
                summary['suspicious_files'] += 1
            else:
                summary['clean_files'] += 1
            
            # Count file types
            filename = result.get('filename', '')
            extension = Path(filename).suffix.lower()
            summary['file_types'][extension] = summary['file_types'].get(extension, 0) + 1
            
            # Count detection methods
            if result.get('yara_analysis', {}).get('matches'):
                summary['yara_detections'] += 1
            
            if result.get('virustotal_analysis', {}).get('is_malicious'):
                summary['vt_detections'] += 1
        
        if threat_scores:
            summary['avg_threat_score'] = sum(threat_scores) / len(threat_scores)
        
        return summary
    
    async def _save_attachment_analysis(self, email_analysis_id: str, attachment_result: Dict):
        """Save attachment analysis results to database."""
        try:
            query = """
            INSERT INTO attachment_analyses 
            (email_analysis_id, filename, file_size, mime_type, file_hash,
             yara_matches, yara_threat_score, is_malware, malware_family)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """
            
            # Extract YARA matches
            yara_matches = []
            yara_threat_score = 0.0
            
            if 'yara_analysis' in attachment_result:
                yara_analysis = attachment_result['yara_analysis']
                yara_threat_score = yara_analysis.get('threat_score', 0.0)
                matches = yara_analysis.get('matches', [])
                yara_matches = [match.get('rule_name', '') for match in matches]
            
            await db_manager.execute_command(
                query,
                email_analysis_id,
                attachment_result.get('filename', ''),
                attachment_result.get('file_size', 0),
                attachment_result.get('mime_type', ''),
                attachment_result.get('file_hash', ''),
                yara_matches,
                yara_threat_score,
                attachment_result.get('is_malware', False),
                attachment_result.get('malware_family', '')
            )
            
        except Exception as e:
            logger.error(f"Failed to save attachment analysis: {e}")
    
    async def get_attachment_statistics(self) -> Dict[str, Any]:
        """Get attachment analysis statistics."""
        try:
            query = """
            SELECT 
                COUNT(*) as total_attachments,
                COUNT(*) FILTER (WHERE is_malware = true) as malware_count,
                AVG(yara_threat_score) as avg_yara_score,
                COUNT(DISTINCT malware_family) FILTER (WHERE malware_family != '') as malware_families,
                COUNT(*) FILTER (WHERE array_length(yara_matches, 1) > 0) as yara_detections
            FROM attachment_analyses
            WHERE analyzed_at > NOW() - INTERVAL '30 days'
            """
            
            results = await db_manager.execute_query(query)
            
            if results:
                return results[0]
            else:
                return {
                    'total_attachments': 0,
                    'malware_count': 0,
                    'avg_yara_score': 0.0,
                    'malware_families': 0,
                    'yara_detections': 0
                }
                
        except Exception as e:
            logger.error(f"Failed to get attachment statistics: {e}")
            return {}
