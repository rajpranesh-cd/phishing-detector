"""Main phishing detection orchestrator."""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid

from ..analyzers.url_analyzer import URLAnalyzer
from ..analyzers.attachment_analyzer import AttachmentAnalyzer
from ..analyzers.header_analyzer import HeaderAnalyzer
from ..ml.model_inference import ModelInference
from ..ml.feature_engineering import FeatureExtractor
from ..utils.database import db_manager
from ..utils.config import settings

logger = logging.getLogger(__name__)


class PhishingDetector:
    """Main orchestrator for comprehensive email threat detection."""
    
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.header_analyzer = HeaderAnalyzer()
        self.model_inference = ModelInference()
        self.feature_extractor = FeatureExtractor()
    
    async def analyze_email_comprehensive(self, email_data: Dict) -> Dict[str, Any]:
        """Perform comprehensive analysis of an email."""
        analysis_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        logger.info(f"Starting comprehensive analysis for email {email_data.get('id', 'unknown')} (Analysis ID: {analysis_id})")
        
        try:
            # Initialize result structure
            result = {
                'analysis_id': analysis_id,
                'email_id': email_data.get('id'),
                'sender_email': email_data.get('sender', {}).get('emailAddress', {}).get('address', ''),
                'subject': email_data.get('subject', ''),
                'overall_threat_score': 0.0,
                'is_phishing': False,
                'confidence_level': 'LOW',
                'threat_category': 'LEGITIMATE',
                'analysis_components': {},
                'recommendations': [],
                'processing_time_ms': 0
            }
            
            # Extract URLs and attachments from email
            urls = self._extract_urls_from_email(email_data)
            attachments = self._extract_attachments_from_email(email_data)
            
            # Run all analyses in parallel
            analysis_tasks = [
                self._analyze_content_and_ml(email_data, urls, attachments),
                self.url_analyzer.analyze_urls(urls, analysis_id),
                self.attachment_analyzer.analyze_attachments(attachments, analysis_id),
                self.header_analyzer.analyze_headers(email_data, analysis_id)
            ]
            
            analysis_results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
            
            # Process results
            ml_result = analysis_results[0] if not isinstance(analysis_results[0], Exception) else {}
            url_result = analysis_results[1] if not isinstance(analysis_results[1], Exception) else {}
            attachment_result = analysis_results[2] if not isinstance(analysis_results[2], Exception) else {}
            header_result = analysis_results[3] if not isinstance(analysis_results[3], Exception) else {}
            
            # Store component results
            result['analysis_components'] = {
                'ml_analysis': ml_result,
                'url_analysis': url_result,
                'attachment_analysis': attachment_result,
                'header_analysis': header_result
            }
            
            # Calculate ensemble score
            ensemble_score = self._calculate_ensemble_score(
                ml_result.get('overall_threat_score', 0.0),
                url_result.get('threat_score', 0.0),
                attachment_result.get('threat_score', 0.0),
                header_result.get('header_score', 0.0),
                ml_result.get('individual_predictions', {})
            )
            
            result['overall_threat_score'] = ensemble_score
            result['is_phishing'] = ensemble_score > settings.confidence_threshold
            result['confidence_level'] = self._determine_confidence_level(ensemble_score)
            result['threat_category'] = self._determine_threat_category(result['analysis_components'])
            
            # Generate recommendations
            result['recommendations'] = self._generate_recommendations(result)
            
            # Calculate processing time
            end_time = datetime.now()
            processing_time = (end_time - start_time).total_seconds() * 1000
            result['processing_time_ms'] = int(processing_time)
            
            # Save comprehensive results to database
            await self._save_email_analysis(result)
            
            logger.info(f"Analysis completed for {analysis_id}: Score={ensemble_score:.3f}, Phishing={result['is_phishing']}, Time={processing_time:.0f}ms")
            
            return result
            
        except Exception as e:
            logger.error(f"Comprehensive email analysis failed for {analysis_id}: {e}")
            return {
                'analysis_id': analysis_id,
                'error': str(e),
                'overall_threat_score': 0.5,
                'is_phishing': False,
                'confidence_level': 'LOW',
                'threat_category': 'UNKNOWN'
            }
    
    async def _analyze_content_and_ml(self, email_data: Dict, urls: List[str], 
                                    attachments: List[Dict]) -> Dict[str, Any]:
        """Analyze email content using ML models."""
        try:
            # Prepare email data for feature extraction
            analysis_data = {
                'subject': email_data.get('subject', ''),
                'body_text': email_data.get('body', {}).get('content', '') if email_data.get('body', {}).get('contentType') == 'text' else '',
                'body_html': email_data.get('body', {}).get('content', '') if email_data.get('body', {}).get('contentType') == 'html' else '',
                'urls': urls,
                'attachments': attachments,
                'headers': email_data.get('internetMessageHeaders', {})
            }
            
            # Get ML prediction
            ml_result = await self.model_inference.predict_single_email(analysis_data)
            
            return ml_result
            
        except Exception as e:
            logger.error(f"ML analysis failed: {e}")
            return {
                'overall_threat_score': 0.5,
                'error': str(e)
            }
    
    def _extract_urls_from_email(self, email_data: Dict) -> List[str]:
        """Extract URLs from email content."""
        urls = []
        
        # Get email body content
        body_content = ''
        if email_data.get('body'):
            body_content = email_data['body'].get('content', '')
        
        # Simple URL extraction (in production, use more sophisticated parsing)
        import re
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        found_urls = re.findall(url_pattern, body_content)
        
        # Clean and deduplicate URLs
        for url in found_urls:
            # Remove trailing punctuation
            url = url.rstrip('.,;!?')
            if url not in urls:
                urls.append(url)
        
        return urls
    
    def _extract_attachments_from_email(self, email_data: Dict) -> List[Dict]:
        """Extract attachment information from email data."""
        attachments = []
        
        if email_data.get('hasAttachments') and email_data.get('attachments'):
            for attachment in email_data['attachments']:
                attachment_info = {
                    'filename': attachment.get('name', ''),
                    'file_size': attachment.get('size', 0),
                    'mime_type': attachment.get('contentType', ''),
                    'file_data': attachment.get('contentBytes')  # Base64 encoded
                }
                attachments.append(attachment_info)
        
        return attachments
    
    def _calculate_ensemble_score(self, content_score: float, url_score: float, 
                                attachment_score: float, header_score: float,
                                ml_predictions: Dict) -> float:
        """Calculate ensemble threat score from all analysis components."""
        
        # Heuristic-based scoring (60% weight)
        heuristic_score = (
            content_score * 0.25 +
            url_score * 0.30 +
            attachment_score * 0.25 +
            header_score * 0.20
        )
        
        # ML-based scoring (40% weight)
        ml_score = 0.5  # Default
        if ml_predictions:
            # Use ensemble prediction if available, otherwise average individual models
            if 'ensemble' in ml_predictions:
                ml_score = ml_predictions['ensemble'].get('probability', 0.5)
            else:
                # Average available model predictions
                valid_predictions = []
                for model_name, prediction in ml_predictions.items():
                    if 'error' not in prediction:
                        valid_predictions.append(prediction.get('probability', 0.5))
                
                if valid_predictions:
                    ml_score = sum(valid_predictions) / len(valid_predictions)
        
        # Combine heuristic and ML scores
        ensemble_score = (heuristic_score * 0.6) + (ml_score * 0.4)
        
        return min(ensemble_score, 1.0)
    
    def _determine_confidence_level(self, threat_score: float) -> str:
        """Determine confidence level based on threat score."""
        if threat_score >= 0.9:
            return 'CRITICAL'
        elif threat_score >= 0.7:
            return 'HIGH'
        elif threat_score >= 0.5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _determine_threat_category(self, analysis_components: Dict) -> str:
        """Determine threat category based on analysis results."""
        ml_analysis = analysis_components.get('ml_analysis', {})
        url_analysis = analysis_components.get('url_analysis', {})
        attachment_analysis = analysis_components.get('attachment_analysis', {})
        
        # Check ML prediction first
        threat_category = ml_analysis.get('threat_category', 'UNKNOWN')
        if threat_category != 'UNKNOWN':
            return threat_category
        
        # Determine based on component analysis
        if attachment_analysis.get('malicious_count', 0) > 0:
            return 'MALWARE'
        elif url_analysis.get('malicious_count', 0) > 0:
            return 'PHISHING'
        elif url_analysis.get('threat_score', 0) > 0.7:
            return 'PHISHING'
        elif ml_analysis.get('overall_threat_score', 0) > 0.5:
            return 'PHISHING'
        else:
            return 'LEGITIMATE'
    
    def _generate_recommendations(self, analysis_result: Dict) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []
        
        threat_score = analysis_result.get('overall_threat_score', 0.0)
        is_phishing = analysis_result.get('is_phishing', False)
        components = analysis_result.get('analysis_components', {})
        
        if is_phishing:
            recommendations.append("QUARANTINE: Move email to quarantine folder immediately")
            recommendations.append("ALERT: Notify recipient about potential phishing attempt")
        
        # URL-specific recommendations
        url_analysis = components.get('url_analysis', {})
        if url_analysis.get('malicious_count', 0) > 0:
            recommendations.append("BLOCK: Block access to malicious URLs")
            recommendations.append("SCAN: Perform additional URL reputation checks")
        
        # Attachment-specific recommendations
        attachment_analysis = components.get('attachment_analysis', {})
        if attachment_analysis.get('malicious_count', 0) > 0:
            recommendations.append("ISOLATE: Quarantine malicious attachments")
            recommendations.append("SCAN: Perform deep malware analysis")
        
        # Header-specific recommendations
        header_analysis = components.get('header_analysis', {})
        if header_analysis.get('header_score', 0) > 0.7:
            recommendations.append("VERIFY: Verify sender authenticity through alternative channels")
            recommendations.append("INVESTIGATE: Review email routing and authentication failures")
        
        # General recommendations based on threat level
        if threat_score > 0.8:
            recommendations.append("ESCALATE: Report to security team for investigation")
            recommendations.append("EDUCATE: Provide phishing awareness training to recipient")
        elif threat_score > 0.5:
            recommendations.append("MONITOR: Increase monitoring for similar threats")
            recommendations.append("CAUTION: Advise recipient to exercise caution")
        
        return recommendations
    
    async def _save_email_analysis(self, analysis_result: Dict):
        """Save comprehensive email analysis to database."""
        try:
            components = analysis_result.get('analysis_components', {})
            ml_analysis = components.get('ml_analysis', {})
            url_analysis = components.get('url_analysis', {})
            attachment_analysis = components.get('attachment_analysis', {})
            header_analysis = components.get('header_analysis', {})
            
            query = """
            INSERT INTO email_analyses 
            (id, message_id, sender_email, subject, overall_threat_score,
             content_score, url_score, attachment_score, header_score,
             random_forest_score, svm_score, deep_learning_score, ensemble_prediction,
             is_phishing, confidence_level, threat_category, analysis_duration_ms)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            """
            
            # Extract ML model scores
            ml_predictions = ml_analysis.get('individual_predictions', {})
            rf_score = ml_predictions.get('random_forest', {}).get('probability')
            svm_score = ml_predictions.get('svm', {}).get('probability')
            dl_score = ml_predictions.get('deep_learning', {}).get('probability')
            ensemble_score = ml_analysis.get('ensemble_prediction', {}).get('probability')
            
            await db_manager.execute_command(
                query,
                analysis_result['analysis_id'],
                analysis_result.get('email_id', ''),
                analysis_result.get('sender_email', ''),
                analysis_result.get('subject', ''),
                analysis_result['overall_threat_score'],
                ml_analysis.get('overall_threat_score', 0.0),
                url_analysis.get('threat_score', 0.0),
                attachment_analysis.get('threat_score', 0.0),
                header_analysis.get('header_score', 0.0),
                rf_score,
                svm_score,
                dl_score,
                ensemble_score,
                analysis_result['is_phishing'],
                analysis_result['confidence_level'],
                analysis_result['threat_category'],
                analysis_result['processing_time_ms']
            )
            
            logger.info(f"Saved analysis results for {analysis_result['analysis_id']}")
            
        except Exception as e:
            logger.error(f"Failed to save email analysis: {e}")
    
    async def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get comprehensive analysis statistics."""
        try:
            query = """
            SELECT 
                COUNT(*) as total_analyses,
                COUNT(*) FILTER (WHERE is_phishing = true) as phishing_detected,
                AVG(overall_threat_score) as avg_threat_score,
                AVG(analysis_duration_ms) as avg_processing_time,
                COUNT(*) FILTER (WHERE confidence_level = 'CRITICAL') as critical_threats,
                COUNT(*) FILTER (WHERE confidence_level = 'HIGH') as high_threats,
                COUNT(*) FILTER (WHERE confidence_level = 'MEDIUM') as medium_threats,
                COUNT(*) FILTER (WHERE confidence_level = 'LOW') as low_threats
            FROM email_analyses
            WHERE processed_at > NOW() - INTERVAL '30 days'
            """
            
            results = await db_manager.execute_query(query)
            
            if results:
                stats = results[0]
                
                # Add component statistics
                url_stats = await self.url_analyzer.get_url_statistics()
                attachment_stats = await self.attachment_analyzer.get_attachment_statistics()
                header_stats = await self.header_analyzer.get_header_statistics()
                
                stats['component_statistics'] = {
                    'url_analysis': url_stats,
                    'attachment_analysis': attachment_stats,
                    'header_analysis': header_stats
                }
                
                return stats
            else:
                return {
                    'total_analyses': 0,
                    'phishing_detected': 0,
                    'avg_threat_score': 0.0,
                    'avg_processing_time': 0.0
                }
                
        except Exception as e:
            logger.error(f"Failed to get analysis statistics: {e}")
            return {}
