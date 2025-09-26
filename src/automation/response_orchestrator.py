"""
Automated Response Orchestration
Transforms from detection-only to automated threat response
"""

import asyncio
from typing import Dict, List, Optional
import logging
from datetime import datetime, timedelta
from enum import Enum
import json

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ResponseAction(Enum):
    QUARANTINE = "quarantine"
    BLOCK_SENDER = "block_sender"
    ALERT_ADMIN = "alert_admin"
    CREATE_INCIDENT = "create_incident"
    SCAN_SIMILAR = "scan_similar"
    UPDATE_RULES = "update_rules"

class AutomatedResponseOrchestrator:
    """Orchestrates automated responses to threats"""
    
    def __init__(self, graph_client, database, notification_service):
        self.graph_client = graph_client
        self.database = database
        self.notification_service = notification_service
        
        # Response rules configuration
        self.response_rules = {
            ThreatLevel.CRITICAL: [
                ResponseAction.QUARANTINE,
                ResponseAction.BLOCK_SENDER,
                ResponseAction.ALERT_ADMIN,
                ResponseAction.CREATE_INCIDENT,
                ResponseAction.SCAN_SIMILAR
            ],
            ThreatLevel.HIGH: [
                ResponseAction.QUARANTINE,
                ResponseAction.ALERT_ADMIN,
                ResponseAction.SCAN_SIMILAR
            ],
            ThreatLevel.MEDIUM: [
                ResponseAction.QUARANTINE,
                ResponseAction.ALERT_ADMIN
            ],
            ThreatLevel.LOW: [
                ResponseAction.ALERT_ADMIN
            ]
        }
        
        # Track response history
        self.response_history = []
    
    async def execute_threat_response(self, threat_analysis: Dict) -> Dict:
        """
        Automatically creates security incidents
        Blocks malicious senders across organization
        Scans for similar threats proactively
        """
        try:
            threat_level = ThreatLevel(threat_analysis.get('threat_level', 'LOW'))
            email_id = threat_analysis.get('email_id')
            sender = threat_analysis.get('sender')
            
            logger.info(f"Executing automated response for threat level: {threat_level.value}")
            
            # Get response actions for this threat level
            actions = self.response_rules.get(threat_level, [])
            
            response_results = {}
            
            # Execute each response action
            for action in actions:
                try:
                    if action == ResponseAction.QUARANTINE:
                        result = await self._quarantine_email(email_id, threat_analysis)
                        response_results['quarantine'] = result
                        
                    elif action == ResponseAction.BLOCK_SENDER:
                        result = await self._block_sender(sender, threat_analysis)
                        response_results['block_sender'] = result
                        
                    elif action == ResponseAction.ALERT_ADMIN:
                        result = await self._alert_administrators(threat_analysis)
                        response_results['alert_admin'] = result
                        
                    elif action == ResponseAction.CREATE_INCIDENT:
                        result = await self._create_security_incident(threat_analysis)
                        response_results['create_incident'] = result
                        
                    elif action == ResponseAction.SCAN_SIMILAR:
                        result = await self._scan_for_similar_threats(threat_analysis)
                        response_results['scan_similar'] = result
                        
                    elif action == ResponseAction.UPDATE_RULES:
                        result = await self._update_detection_rules(threat_analysis)
                        response_results['update_rules'] = result
                        
                except Exception as e:
                    logger.error(f"Failed to execute {action.value}: {e}")
                    response_results[action.value] = {'error': str(e)}
            
            # Log response execution
            response_record = {
                'timestamp': datetime.utcnow().isoformat(),
                'threat_level': threat_level.value,
                'email_id': email_id,
                'sender': sender,
                'actions_executed': list(response_results.keys()),
                'results': response_results
            }
            
            self.response_history.append(response_record)
            
            # Store in database
            await self._log_response_to_database(response_record)
            
            return {
                'success': True,
                'threat_level': threat_level.value,
                'actions_executed': len(response_results),
                'response_details': response_results,
                'response_id': response_record.get('response_id')
            }
            
        except Exception as e:
            logger.error(f"Automated response execution failed: {e}")
            return {'error': str(e)}
    
    async def _quarantine_email(self, email_id: str, threat_analysis: Dict) -> Dict:
        """Quarantine the malicious email"""
        try:
            # Move email to quarantine folder
            result = await self.graph_client.move_to_quarantine(email_id)
            
            if result.get('success'):
                # Update database
                await self.database.update_email_status(email_id, 'quarantined')
                
                return {
                    'success': True,
                    'action': 'Email quarantined successfully',
                    'quarantine_folder': result.get('quarantine_folder')
                }
            else:
                return {'success': False, 'error': result.get('error')}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _block_sender(self, sender: str, threat_analysis: Dict) -> Dict:
        """Block sender across the organization"""
        try:
            # Add sender to blocked senders list
            result = await self.graph_client.add_blocked_sender(sender)
            
            if result.get('success'):
                # Update database
                await self.database.add_blocked_sender(
                    sender, 
                    reason=f"Automated block due to {threat_analysis.get('threat_level')} threat",
                    threat_score=threat_analysis.get('threat_score', 0)
                )
                
                return {
                    'success': True,
                    'action': f'Sender {sender} blocked organization-wide',
                    'block_type': 'organization_wide'
                }
            else:
                return {'success': False, 'error': result.get('error')}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _alert_administrators(self, threat_analysis: Dict) -> Dict:
        """Send alerts to security administrators"""
        try:
            alert_message = self._generate_alert_message(threat_analysis)
            
            # Send notifications through multiple channels
            notification_results = await asyncio.gather(
                self.notification_service.send_email_alert(alert_message),
                self.notification_service.send_slack_alert(alert_message),
                self.notification_service.send_teams_alert(alert_message),
                return_exceptions=True
            )
            
            successful_notifications = sum(1 for result in notification_results 
                                         if isinstance(result, dict) and result.get('success'))
            
            return {
                'success': True,
                'notifications_sent': successful_notifications,
                'total_channels': len(notification_results),
                'alert_message': alert_message
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _create_security_incident(self, threat_analysis: Dict) -> Dict:
        """Create a security incident in the SIEM/ticketing system"""
        try:
            incident_data = {
                'title': f"Phishing Email Detected - {threat_analysis.get('threat_level')} Risk",
                'description': self._generate_incident_description(threat_analysis),
                'severity': threat_analysis.get('threat_level', 'MEDIUM'),
                'category': 'Email Security',
                'source': 'AI Phishing Detector',
                'timestamp': datetime.utcnow().isoformat(),
                'evidence': threat_analysis
            }
            
            # Create incident in external system (placeholder)
            incident_id = await self._create_external_incident(incident_data)
            
            # Store incident in database
            await self.database.create_security_incident(incident_data, incident_id)
            
            return {
                'success': True,
                'incident_id': incident_id,
                'incident_title': incident_data['title']
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _scan_for_similar_threats(self, threat_analysis: Dict) -> Dict:
        """Proactively scan for similar threats in the organization"""
        try:
            # Extract threat indicators
            indicators = self._extract_threat_indicators(threat_analysis)
            
            # Search for similar emails
            similar_emails = await self._search_similar_emails(indicators)
            
            # Analyze found emails
            analysis_tasks = []
            for email in similar_emails:
                analysis_tasks.append(self._analyze_similar_email(email, threat_analysis))
            
            analysis_results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
            
            # Count threats found
            threats_found = sum(1 for result in analysis_results 
                              if isinstance(result, dict) and result.get('is_threat'))
            
            return {
                'success': True,
                'emails_scanned': len(similar_emails),
                'threats_found': threats_found,
                'indicators_used': indicators,
                'scan_results': analysis_results
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _update_detection_rules(self, threat_analysis: Dict) -> Dict:
        """Update detection rules based on new threat patterns"""
        try:
            # Extract new patterns from threat analysis
            new_patterns = self._extract_detection_patterns(threat_analysis)
            
            # Update rule database
            rules_updated = 0
            for pattern in new_patterns:
                success = await self.database.add_detection_rule(pattern)
                if success:
                    rules_updated += 1
            
            return {
                'success': True,
                'rules_updated': rules_updated,
                'new_patterns': new_patterns
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _generate_alert_message(self, threat_analysis: Dict) -> Dict:
        """Generate alert message for administrators"""
        return {
            'subject': f"🚨 {threat_analysis.get('threat_level')} Threat Detected",
            'body': f"""
            A {threat_analysis.get('threat_level')} level threat has been detected and automatically processed.
            
            Email Details:
            - Sender: {threat_analysis.get('sender')}
            - Subject: {threat_analysis.get('subject')}
            - Threat Score: {threat_analysis.get('threat_score', 0):.2f}
            - Detection Time: {threat_analysis.get('analysis_timestamp')}
            
            Threat Analysis:
            - Phishing Probability: {threat_analysis.get('phishing_probability', 0):.2f}
            - Scam Indicators: {len(threat_analysis.get('scam_indicators', []))}
            - Malicious URLs: {len(threat_analysis.get('malicious_urls', []))}
            
            Automated Actions Taken:
            - Email quarantined
            - Sender analysis initiated
            - Similar threat scan started
            
            Please review the threat analysis in the security dashboard.
            """,
            'priority': 'HIGH' if threat_analysis.get('threat_level') in ['HIGH', 'CRITICAL'] else 'MEDIUM'
        }
    
    def _generate_incident_description(self, threat_analysis: Dict) -> str:
        """Generate detailed incident description"""
        return f"""
        Automated phishing detection system identified a {threat_analysis.get('threat_level')} level threat.
        
        Email Information:
        - Message ID: {threat_analysis.get('email_id')}
        - From: {threat_analysis.get('sender')}
        - To: {threat_analysis.get('recipients')}
        - Subject: {threat_analysis.get('subject')}
        - Received: {threat_analysis.get('received_time')}
        
        Threat Analysis Results:
        - Overall Threat Score: {threat_analysis.get('threat_score', 0):.3f}
        - Phishing Probability: {threat_analysis.get('phishing_probability', 0):.3f}
        - Scam Score: {threat_analysis.get('scam_score', 0):.3f}
        - URL Threats: {len(threat_analysis.get('malicious_urls', []))}
        - Attachment Threats: {len(threat_analysis.get('malicious_attachments', []))}
        
        Detection Methods:
        - Machine Learning Models: {threat_analysis.get('ml_models_used', [])}
        - Threat Intelligence: {threat_analysis.get('threat_intel_sources', [])}
        - Behavioral Analysis: {threat_analysis.get('behavioral_anomalies', [])}
        
        Automated Response Actions:
        - Email quarantined automatically
        - Sender added to monitoring list
        - Similar threat scan initiated
        - Security team notified
        
        Next Steps:
        1. Review quarantined email in security dashboard
        2. Verify threat classification accuracy
        3. Update detection rules if needed
        4. Monitor for similar threats
        """
    
    async def _create_external_incident(self, incident_data: Dict) -> str:
        """Create incident in external SIEM/ticketing system"""
        # Placeholder for external system integration
        # Could integrate with ServiceNow, Jira, Splunk, etc.
        incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        return incident_id
    
    def _extract_threat_indicators(self, threat_analysis: Dict) -> List[str]:
        """Extract threat indicators for similarity search"""
        indicators = []
        
        # Add sender domain
        sender = threat_analysis.get('sender', '')
        if '@' in sender:
            domain = sender.split('@')[1]
            indicators.append(f"sender_domain:{domain}")
        
        # Add malicious URLs
        for url in threat_analysis.get('malicious_urls', []):
            indicators.append(f"url:{url}")
        
        # Add subject keywords
        subject = threat_analysis.get('subject', '')
        if subject:
            # Extract key terms (simplified)
            keywords = [word.lower() for word in subject.split() if len(word) > 3]
            for keyword in keywords[:3]:  # Top 3 keywords
                indicators.append(f"subject_keyword:{keyword}")
        
        return indicators
    
    async def _search_similar_emails(self, indicators: List[str]) -> List[Dict]:
        """Search for emails with similar threat indicators"""
        # Placeholder implementation
        # Would search email database for similar patterns
        return []
    
    async def _analyze_similar_email(self, email: Dict, original_threat: Dict) -> Dict:
        """Analyze potentially similar email"""
        # Placeholder implementation
        # Would run full threat analysis on similar email
        return {'is_threat': False, 'similarity_score': 0.0}
    
    def _extract_detection_patterns(self, threat_analysis: Dict) -> List[Dict]:
        """Extract new detection patterns from threat analysis"""
        patterns = []
        
        # Extract URL patterns
        for url in threat_analysis.get('malicious_urls', []):
            patterns.append({
                'type': 'url_pattern',
                'pattern': url,
                'confidence': 0.8,
                'source': 'automated_analysis'
            })
        
        # Extract sender patterns
        sender = threat_analysis.get('sender', '')
        if sender:
            patterns.append({
                'type': 'sender_pattern',
                'pattern': sender,
                'confidence': 0.7,
                'source': 'automated_analysis'
            })
        
        return patterns
    
    async def _log_response_to_database(self, response_record: Dict):
        """Log response execution to database"""
        try:
            await self.database.log_automated_response(response_record)
        except Exception as e:
            logger.error(f"Failed to log response to database: {e}")
    
    async def get_response_statistics(self, days: int = 30) -> Dict:
        """Get automated response statistics"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Filter recent responses
            recent_responses = [
                r for r in self.response_history 
                if datetime.fromisoformat(r['timestamp']) > cutoff_date
            ]
            
            # Calculate statistics
            total_responses = len(recent_responses)
            threat_level_counts = {}
            action_counts = {}
            
            for response in recent_responses:
                # Count by threat level
                level = response['threat_level']
                threat_level_counts[level] = threat_level_counts.get(level, 0) + 1
                
                # Count by actions
                for action in response['actions_executed']:
                    action_counts[action] = action_counts.get(action, 0) + 1
            
            return {
                'period_days': days,
                'total_responses': total_responses,
                'threat_level_breakdown': threat_level_counts,
                'action_breakdown': action_counts,
                'avg_responses_per_day': total_responses / days if days > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Failed to get response statistics: {e}")
            return {'error': str(e)}
