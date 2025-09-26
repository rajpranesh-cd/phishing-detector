#!/usr/bin/env python3
"""
Single User Email Inbox Analysis Test Script
Follows the workflow diagram for comprehensive email security testing
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from integrations.graph_api import GraphAPIClient
from core.phishing_detector import PhishingDetector
from analyzers.url_analyzer import URLAnalyzer
from analyzers.attachment_analyzer import AttachmentAnalyzer
from analyzers.header_analyzer import HeaderAnalyzer
from ml.model_inference import ModelInference
from utils.database import get_db_connection
from utils.config import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SingleUserTester:
    """Test the complete email analysis workflow for a single user"""
    
    def __init__(self, user_email: str):
        self.user_email = user_email
        self.settings = get_settings()
        self.graph_client = GraphAPIClient()
        self.phishing_detector = PhishingDetector()
        self.results = {
            'total_emails': 0,
            'whitelisted': 0,
            'low_risk': 0,
            'medium_risk': 0,
            'high_risk': 0,
            'quarantined': 0,
            'manual_review': 0,
            'processing_errors': 0,
            'detailed_results': []
        }
        
        # Whitelist configuration
        self.whitelist_domains = {
            'microsoft.com', 'office.com', 'outlook.com',
            'google.com', 'gmail.com', 'github.com',
            'linkedin.com', 'amazon.com', 'apple.com'
        }
        
        # Risk thresholds matching the workflow
        self.risk_thresholds = {
            'low': 0.3,      # Below 0.3 = Low Risk
            'medium': 0.7,   # 0.3-0.7 = Medium Risk  
            'high': 0.7      # Above 0.7 = High Risk
        }

    async def analyze_user_inbox(self, days_back: int = 7) -> Dict:
        """
        Analyze a single user's inbox following the workflow diagram
        
        Args:
            days_back: Number of days to look back for emails
            
        Returns:
            Analysis results dictionary
        """
        logger.info(f"Starting inbox analysis for user: {self.user_email}")
        logger.info(f"Analyzing emails from the last {days_back} days")
        
        try:
            # Step 1: Email Arrives (Get emails from inbox)
            emails = await self._get_user_emails(days_back)
            self.results['total_emails'] = len(emails)
            
            logger.info(f"Found {len(emails)} emails to analyze")
            
            # Process each email through the workflow
            for i, email in enumerate(emails, 1):
                logger.info(f"Processing email {i}/{len(emails)}: {email.get('subject', 'No Subject')[:50]}...")
                
                try:
                    result = await self._process_email_workflow(email)
                    self.results['detailed_results'].append(result)
                    
                    # Update counters
                    risk_level = result['risk_level']
                    action = result['action']
                    
                    if result['whitelisted']:
                        self.results['whitelisted'] += 1
                    elif risk_level == 'low':
                        self.results['low_risk'] += 1
                    elif risk_level == 'medium':
                        self.results['medium_risk'] += 1
                    elif risk_level == 'high':
                        self.results['high_risk'] += 1
                        
                    if action == 'quarantine':
                        self.results['quarantined'] += 1
                    elif action == 'manual_review':
                        self.results['manual_review'] += 1
                        
                except Exception as e:
                    logger.error(f"Error processing email {i}: {str(e)}")
                    self.results['processing_errors'] += 1
                    
            # Generate final report
            await self._generate_test_report()
            
            return self.results
            
        except Exception as e:
            logger.error(f"Error in inbox analysis: {str(e)}")
            raise

    async def _get_user_emails(self, days_back: int) -> List[Dict]:
        """Get emails from user's inbox"""
        try:
            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            # Get emails using Graph API
            emails = await self.graph_client.get_user_emails(
                user_id=self.user_email,
                folder='inbox',
                start_date=start_date,
                end_date=end_date,
                limit=100  # Limit for testing
            )
            
            return emails
            
        except Exception as e:
            logger.error(f"Error fetching emails: {str(e)}")
            return []

    async def _process_email_workflow(self, email: Dict) -> Dict:
        """
        Process single email through the complete workflow diagram
        
        Workflow Steps:
        1. Email Arrives ✓
        2. Webhook Notify (simulated)
        3. Graph API Extract ✓
        4. Whitelist Check
        5. Heuristic Analysis (if not whitelisted)
        6. AI Security Analysis
        7. Score Combination
        8. Threshold Check
        9. Action Decision
        """
        
        email_id = email.get('id', 'unknown')
        subject = email.get('subject', 'No Subject')
        sender = email.get('from', {}).get('emailAddress', {}).get('address', 'unknown')
        
        result = {
            'email_id': email_id,
            'subject': subject,
            'sender': sender,
            'timestamp': datetime.now().isoformat(),
            'whitelisted': False,
            'risk_score': 0.0,
            'risk_level': 'low',
            'action': 'release',
            'analysis_details': {},
            'threats_detected': []
        }
        
        try:
            # Step 4: Whitelist Check
            if self._is_whitelisted(sender):
                logger.info(f"Email from {sender} is whitelisted - releasing")
                result['whitelisted'] = True
                result['action'] = 'release'
                return result
            
            # Step 5: Heuristic Analysis + Step 6: AI Security Analysis
            logger.info(f"Running security analysis on email from {sender}")
            analysis_result = await self.phishing_detector.analyze_email(email)
            
            # Step 7: Score Combination
            risk_score = analysis_result.get('risk_score', 0.0)
            result['risk_score'] = risk_score
            result['analysis_details'] = analysis_result
            result['threats_detected'] = analysis_result.get('threats_detected', [])
            
            # Step 8: Threshold Check + Action Decision
            if risk_score >= self.risk_thresholds['high']:
                result['risk_level'] = 'high'
                result['action'] = 'quarantine'
                logger.warning(f"HIGH RISK email detected: {subject[:50]} (Score: {risk_score:.3f})")
                
            elif risk_score >= self.risk_thresholds['low']:
                result['risk_level'] = 'medium'
                result['action'] = 'security_forward'  # Could be manual review
                logger.info(f"MEDIUM RISK email: {subject[:50]} (Score: {risk_score:.3f})")
                
            else:
                result['risk_level'] = 'low'
                result['action'] = 'manual_review'  # Low risk still gets reviewed
                logger.info(f"LOW RISK email: {subject[:50]} (Score: {risk_score:.3f})")
            
            # Simulate manual review decision for medium/low risk
            if result['action'] in ['security_forward', 'manual_review']:
                # In real implementation, this would be human review
                # For testing, we'll simulate based on threat indicators
                if len(result['threats_detected']) > 2:
                    result['action'] = 'quarantine'
                    self.results['quarantined'] += 1
                else:
                    result['action'] = 'release'
            
            return result
            
        except Exception as e:
            logger.error(f"Error in email workflow processing: {str(e)}")
            result['error'] = str(e)
            return result

    def _is_whitelisted(self, sender_email: str) -> bool:
        """Check if sender is whitelisted"""
        if not sender_email:
            return False
            
        domain = sender_email.split('@')[-1].lower()
        return domain in self.whitelist_domains

    async def _generate_test_report(self):
        """Generate comprehensive test report"""
        
        report = {
            'test_summary': {
                'user_email': self.user_email,
                'test_timestamp': datetime.now().isoformat(),
                'total_emails_analyzed': self.results['total_emails'],
                'processing_errors': self.results['processing_errors']
            },
            'workflow_results': {
                'whitelisted_emails': self.results['whitelisted'],
                'low_risk_emails': self.results['low_risk'],
                'medium_risk_emails': self.results['medium_risk'],
                'high_risk_emails': self.results['high_risk'],
                'quarantined_emails': self.results['quarantined'],
                'manual_review_emails': self.results['manual_review']
            },
            'threat_detection_summary': self._analyze_threats(),
            'performance_metrics': self._calculate_performance_metrics()
        }
        
        # Save detailed report
        report_file = f"test_results_{self.user_email.replace('@', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump({
                'report': report,
                'detailed_results': self.results['detailed_results']
            }, f, indent=2)
        
        logger.info(f"Test report saved to: {report_file}")
        
        # Print summary to console
        self._print_summary_report(report)

    def _analyze_threats(self) -> Dict:
        """Analyze types of threats detected"""
        threat_summary = {
            'phishing_attempts': 0,
            'malicious_urls': 0,
            'suspicious_attachments': 0,
            'spoofed_senders': 0,
            'social_engineering': 0
        }
        
        for result in self.results['detailed_results']:
            threats = result.get('threats_detected', [])
            for threat in threats:
                threat_type = threat.get('type', '').lower()
                if 'phishing' in threat_type:
                    threat_summary['phishing_attempts'] += 1
                elif 'url' in threat_type:
                    threat_summary['malicious_urls'] += 1
                elif 'attachment' in threat_type:
                    threat_summary['suspicious_attachments'] += 1
                elif 'spoof' in threat_type:
                    threat_summary['spoofed_senders'] += 1
                elif 'social' in threat_type:
                    threat_summary['social_engineering'] += 1
        
        return threat_summary

    def _calculate_performance_metrics(self) -> Dict:
        """Calculate performance metrics"""
        total = self.results['total_emails']
        if total == 0:
            return {}
        
        return {
            'whitelist_rate': (self.results['whitelisted'] / total) * 100,
            'threat_detection_rate': ((self.results['medium_risk'] + self.results['high_risk']) / total) * 100,
            'quarantine_rate': (self.results['quarantined'] / total) * 100,
            'manual_review_rate': (self.results['manual_review'] / total) * 100,
            'error_rate': (self.results['processing_errors'] / total) * 100
        }

    def _print_summary_report(self, report: Dict):
        """Print summary report to console"""
        print("\n" + "="*80)
        print("AI PHISHING DETECTION SYSTEM - SINGLE USER TEST RESULTS")
        print("="*80)
        
        summary = report['test_summary']
        print(f"User Email: {summary['user_email']}")
        print(f"Test Date: {summary['test_timestamp']}")
        print(f"Total Emails Analyzed: {summary['total_emails_analyzed']}")
        print(f"Processing Errors: {summary['processing_errors']}")
        
        print("\nWORKFLOW RESULTS:")
        print("-" * 40)
        workflow = report['workflow_results']
        print(f"Whitelisted Emails: {workflow['whitelisted_emails']}")
        print(f"Low Risk Emails: {workflow['low_risk_emails']}")
        print(f"Medium Risk Emails: {workflow['medium_risk_emails']}")
        print(f"High Risk Emails: {workflow['high_risk_emails']}")
        print(f"Quarantined Emails: {workflow['quarantined_emails']}")
        print(f"Manual Review Emails: {workflow['manual_review_emails']}")
        
        print("\nTHREAT DETECTION SUMMARY:")
        print("-" * 40)
        threats = report['threat_detection_summary']
        for threat_type, count in threats.items():
            print(f"{threat_type.replace('_', ' ').title()}: {count}")
        
        print("\nPERFORMANCE METRICS:")
        print("-" * 40)
        metrics = report['performance_metrics']
        for metric, value in metrics.items():
            print(f"{metric.replace('_', ' ').title()}: {value:.2f}%")
        
        print("\n" + "="*80)


async def main():
    """Main function to run the single user test"""
    
    if len(sys.argv) != 2:
        print("Usage: python test_single_user.py <user_email>")
        print("Example: python test_single_user.py john.doe@company.com")
        sys.exit(1)
    
    user_email = sys.argv[1]
    
    print(f"Starting AI Phishing Detection Test for user: {user_email}")
    print("This will analyze the user's inbox following the complete workflow diagram")
    print("-" * 80)
    
    try:
        tester = SingleUserTester(user_email)
        results = await tester.analyze_user_inbox(days_back=7)
        
        print("\nTest completed successfully!")
        print(f"Check the generated JSON report for detailed results.")
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        print(f"Test failed with error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
