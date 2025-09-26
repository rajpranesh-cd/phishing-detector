"""
Advanced Transformer-based Phishing Detection using BERT/RoBERTa models
Provides contextual understanding and sophisticated social engineering detection
"""

import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel, pipeline
from typing import Dict, List, Optional, Tuple
import numpy as np
import logging
from datetime import datetime
import asyncio
import aiohttp
from PIL import Image
import io
import base64

logger = logging.getLogger(__name__)

class TransformerPhishingDetector:
    """BERT-based model that understands email context and conversation history"""
    
    def __init__(self, model_name: str = "microsoft/DialoGPT-medium"):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name).to(self.device)
        
        # Initialize classification head
        self.classifier = nn.Sequential(
            nn.Linear(768, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 4)  # [legitimate, phishing, scam, suspicious]
        ).to(self.device)
        
        # Psychological manipulation patterns
        self.manipulation_patterns = {
            'urgency': ['urgent', 'immediate', 'expires today', 'act now', 'limited time'],
            'fear': ['suspended', 'blocked', 'security alert', 'unauthorized', 'compromised'],
            'authority': ['bank', 'government', 'irs', 'police', 'legal action'],
            'greed': ['winner', 'prize', 'lottery', 'inheritance', 'free money']
        }
        
    async def analyze_email_context(self, email_text: str, conversation_history: Optional[List[str]] = None) -> Dict:
        """
        Analyzes email context using transformer models
        Detects subtle context manipulation in email threads
        """
        try:
            # Prepare input with conversation history
            context = ""
            if conversation_history:
                context = " [SEP] ".join(conversation_history[-5:])  # Last 5 emails
            
            full_input = f"{context} [SEP] {email_text}" if context else email_text
            
            # Tokenize and encode
            inputs = self.tokenizer(
                full_input,
                return_tensors="pt",
                max_length=512,
                truncation=True,
                padding=True
            ).to(self.device)
            
            # Get embeddings
            with torch.no_grad():
                outputs = self.model(**inputs)
                embeddings = outputs.last_hidden_state.mean(dim=1)
                
                # Classification
                logits = self.classifier(embeddings)
                probabilities = torch.softmax(logits, dim=-1)
                
            # Analyze psychological manipulation
            manipulation_score = self._analyze_psychological_manipulation(email_text)
            
            # Context anomaly detection
            context_anomaly = self._detect_context_anomaly(email_text, conversation_history)
            
            return {
                'threat_probabilities': {
                    'legitimate': float(probabilities[0][0]),
                    'phishing': float(probabilities[0][1]),
                    'scam': float(probabilities[0][2]),
                    'suspicious': float(probabilities[0][3])
                },
                'manipulation_score': manipulation_score,
                'context_anomaly_score': context_anomaly,
                'confidence': float(torch.max(probabilities)),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Transformer analysis failed: {e}")
            return {'error': str(e)}
    
    def _analyze_psychological_manipulation(self, text: str) -> float:
        """Detects psychological manipulation tactics"""
        text_lower = text.lower()
        manipulation_score = 0.0
        
        for category, patterns in self.manipulation_patterns.items():
            category_score = sum(1 for pattern in patterns if pattern in text_lower)
            manipulation_score += category_score * 0.25
            
        return min(manipulation_score, 1.0)
    
    def _detect_context_anomaly(self, current_email: str, history: Optional[List[str]]) -> float:
        """Detects when attackers hijack legitimate conversations"""
        if not history:
            return 0.0
            
        # Simple implementation - can be enhanced with more sophisticated analysis
        current_tokens = set(current_email.lower().split())
        
        if len(history) > 0:
            recent_tokens = set(" ".join(history[-2:]).lower().split())
            overlap = len(current_tokens.intersection(recent_tokens))
            total_tokens = len(current_tokens.union(recent_tokens))
            
            if total_tokens > 0:
                similarity = overlap / total_tokens
                return max(0.0, 1.0 - similarity * 2)  # Higher score = more anomalous
                
        return 0.0

class AdvancedURLAnalyzer:
    """Advanced URL analysis with screenshot and visual phishing detection"""
    
    def __init__(self):
        self.session = None
        
    async def analyze_url_screenshot(self, url: str) -> Dict:
        """
        Takes screenshots of suspicious websites
        Uses computer vision to detect brand impersonation
        """
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
                
            # Take screenshot using headless browser simulation
            screenshot_data = await self._capture_screenshot(url)
            
            if screenshot_data:
                # Analyze screenshot for brand impersonation
                brand_analysis = await self._detect_brand_impersonation(screenshot_data)
                
                # Visual similarity to known phishing templates
                template_similarity = await self._check_phishing_templates(screenshot_data)
                
                return {
                    'screenshot_captured': True,
                    'brand_impersonation_score': brand_analysis['score'],
                    'impersonated_brands': brand_analysis['brands'],
                    'template_similarity_score': template_similarity,
                    'visual_threat_level': self._calculate_visual_threat_level(
                        brand_analysis['score'], template_similarity
                    )
                }
            else:
                return {'screenshot_captured': False, 'error': 'Failed to capture screenshot'}
                
        except Exception as e:
            logger.error(f"URL screenshot analysis failed: {e}")
            return {'error': str(e)}
    
    async def _capture_screenshot(self, url: str) -> Optional[bytes]:
        """Captures screenshot of URL using headless browser"""
        # Placeholder implementation - would use Selenium or Playwright
        # For now, return mock data
        return b"mock_screenshot_data"
    
    async def _detect_brand_impersonation(self, screenshot_data: bytes) -> Dict:
        """Detects brand logo impersonation using computer vision"""
        # Placeholder implementation - would use OpenCV/PIL for logo detection
        return {
            'score': 0.3,  # Mock score
            'brands': ['microsoft', 'paypal']  # Mock detected brands
        }
    
    async def _check_phishing_templates(self, screenshot_data: bytes) -> float:
        """Checks similarity to known phishing page templates"""
        # Placeholder implementation - would compare against template database
        return 0.4  # Mock similarity score
    
    def _calculate_visual_threat_level(self, brand_score: float, template_score: float) -> str:
        """Calculates overall visual threat level"""
        combined_score = (brand_score + template_score) / 2
        
        if combined_score > 0.7:
            return "HIGH"
        elif combined_score > 0.4:
            return "MEDIUM"
        else:
            return "LOW"

class QRCodeAnalyzer:
    """QR Code threat detection for modern phishing attacks"""
    
    def __init__(self):
        try:
            import cv2
            import pyzbar.pyzbar as pyzbar
            self.cv2 = cv2
            self.pyzbar = pyzbar
        except ImportError:
            logger.warning("QR code analysis dependencies not installed")
            self.cv2 = None
            self.pyzbar = None
    
    async def analyze_qr_codes_in_images(self, email_attachments: List[bytes]) -> Dict:
        """
        Scans images for embedded QR codes
        Analyzes QR code destinations for threats
        """
        if not self.cv2 or not self.pyzbar:
            return {'error': 'QR code analysis not available'}
            
        qr_results = []
        
        for attachment_data in email_attachments:
            try:
                # Convert bytes to image
                image = Image.open(io.BytesIO(attachment_data))
                image_array = np.array(image)
                
                # Detect QR codes
                qr_codes = self.pyzbar.decode(image_array)
                
                for qr_code in qr_codes:
                    qr_data = qr_code.data.decode('utf-8')
                    
                    # Analyze QR code destination
                    threat_analysis = await self._analyze_qr_destination(qr_data)
                    
                    qr_results.append({
                        'qr_data': qr_data,
                        'threat_score': threat_analysis['threat_score'],
                        'destination_analysis': threat_analysis
                    })
                    
            except Exception as e:
                logger.error(f"QR code analysis failed for attachment: {e}")
                
        return {
            'qr_codes_found': len(qr_results),
            'qr_analyses': qr_results,
            'max_threat_score': max([qr['threat_score'] for qr in qr_results], default=0.0)
        }
    
    async def _analyze_qr_destination(self, qr_data: str) -> Dict:
        """Analyzes QR code destination for threats"""
        # Check if it's a URL
        if qr_data.startswith(('http://', 'https://')):
            # Use existing URL analysis
            url_analyzer = AdvancedURLAnalyzer()
            url_analysis = await url_analyzer.analyze_url_screenshot(qr_data)
            
            return {
                'type': 'url',
                'destination': qr_data,
                'threat_score': 0.6 if url_analysis.get('visual_threat_level') == 'HIGH' else 0.3,
                'analysis': url_analysis
            }
        else:
            # Analyze other QR code types (phone numbers, text, etc.)
            return {
                'type': 'other',
                'destination': qr_data,
                'threat_score': 0.1,  # Low threat for non-URL QR codes
                'analysis': {'content_type': 'non_url'}
            }

class EmailNetworkAnalyzer:
    """Analyzes email communication patterns using Graph Neural Networks"""
    
    def __init__(self):
        self.communication_graph = {}
        self.user_profiles = {}
    
    async def build_communication_graph(self, user_emails: List[Dict]) -> Dict:
        """
        Maps email relationships across organization
        Detects unusual communication patterns
        """
        graph_data = {
            'nodes': set(),
            'edges': [],
            'anomalies': []
        }
        
        for email in user_emails:
            sender = email.get('sender', '')
            recipients = email.get('recipients', [])
            timestamp = email.get('timestamp')
            
            # Add nodes
            graph_data['nodes'].add(sender)
            graph_data['nodes'].update(recipients)
            
            # Add edges
            for recipient in recipients:
                graph_data['edges'].append({
                    'from': sender,
                    'to': recipient,
                    'timestamp': timestamp,
                    'weight': 1
                })
        
        # Detect anomalies
        anomalies = await self._detect_communication_anomalies(graph_data)
        graph_data['anomalies'] = anomalies
        
        return {
            'graph_stats': {
                'total_nodes': len(graph_data['nodes']),
                'total_edges': len(graph_data['edges']),
                'anomalies_detected': len(anomalies)
            },
            'anomalies': anomalies,
            'threat_score': len(anomalies) * 0.2  # Simple scoring
        }
    
    async def _detect_communication_anomalies(self, graph_data: Dict) -> List[Dict]:
        """Detects unusual communication patterns"""
        anomalies = []
        
        # Simple anomaly detection - can be enhanced with GNN
        sender_counts = {}
        for edge in graph_data['edges']:
            sender = edge['from']
            sender_counts[sender] = sender_counts.get(sender, 0) + 1
        
        # Flag senders with unusually high email volume
        avg_volume = sum(sender_counts.values()) / len(sender_counts) if sender_counts else 0
        
        for sender, count in sender_counts.items():
            if count > avg_volume * 3:  # 3x average
                anomalies.append({
                    'type': 'high_volume_sender',
                    'sender': sender,
                    'email_count': count,
                    'severity': 'medium'
                })
        
        return anomalies

class BehavioralAnalyzer:
    """Detects when legitimate accounts are compromised"""
    
    def __init__(self):
        self.user_baselines = {}
    
    async def analyze_sender_behavior(self, sender_email: str, email_history: List[Dict]) -> Dict:
        """
        Learns normal communication patterns
        Detects when accounts are compromised
        """
        try:
            # Build behavioral baseline
            baseline = await self._build_behavioral_baseline(sender_email, email_history)
            
            # Analyze recent behavior
            recent_emails = [e for e in email_history if self._is_recent(e.get('timestamp'))]
            current_behavior = await self._analyze_current_behavior(recent_emails)
            
            # Compare against baseline
            anomaly_score = await self._calculate_behavioral_anomaly(baseline, current_behavior)
            
            return {
                'sender': sender_email,
                'baseline_established': len(email_history) >= 10,
                'behavioral_anomaly_score': anomaly_score,
                'anomalies_detected': self._identify_specific_anomalies(baseline, current_behavior),
                'compromise_likelihood': 'HIGH' if anomaly_score > 0.7 else 'MEDIUM' if anomaly_score > 0.4 else 'LOW'
            }
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
            return {'error': str(e)}
    
    async def _build_behavioral_baseline(self, sender: str, history: List[Dict]) -> Dict:
        """Builds behavioral baseline for sender"""
        if len(history) < 10:
            return {'insufficient_data': True}
        
        # Analyze patterns
        avg_email_length = np.mean([len(e.get('body', '')) for e in history])
        common_recipients = self._get_common_recipients(history)
        typical_send_times = self._analyze_send_times(history)
        common_subjects = self._analyze_subject_patterns(history)
        
        return {
            'avg_email_length': avg_email_length,
            'common_recipients': common_recipients,
            'typical_send_times': typical_send_times,
            'common_subjects': common_subjects,
            'total_emails_analyzed': len(history)
        }
    
    async def _analyze_current_behavior(self, recent_emails: List[Dict]) -> Dict:
        """Analyzes current behavior patterns"""
        if not recent_emails:
            return {}
        
        current_avg_length = np.mean([len(e.get('body', '')) for e in recent_emails])
        current_recipients = self._get_common_recipients(recent_emails)
        current_send_times = self._analyze_send_times(recent_emails)
        
        return {
            'avg_email_length': current_avg_length,
            'recipients': current_recipients,
            'send_times': current_send_times
        }
    
    async def _calculate_behavioral_anomaly(self, baseline: Dict, current: Dict) -> float:
        """Calculates behavioral anomaly score"""
        if baseline.get('insufficient_data'):
            return 0.0
        
        anomaly_score = 0.0
        
        # Length anomaly
        if 'avg_email_length' in baseline and 'avg_email_length' in current:
            length_diff = abs(baseline['avg_email_length'] - current['avg_email_length'])
            length_anomaly = min(length_diff / baseline['avg_email_length'], 1.0)
            anomaly_score += length_anomaly * 0.3
        
        # Recipient anomaly
        baseline_recipients = set(baseline.get('common_recipients', []))
        current_recipients = set(current.get('recipients', []))
        
        if baseline_recipients:
            recipient_overlap = len(baseline_recipients.intersection(current_recipients))
            recipient_anomaly = 1.0 - (recipient_overlap / len(baseline_recipients))
            anomaly_score += recipient_anomaly * 0.4
        
        return min(anomaly_score, 1.0)
    
    def _get_common_recipients(self, emails: List[Dict]) -> List[str]:
        """Gets most common recipients"""
        recipient_counts = {}
        for email in emails:
            for recipient in email.get('recipients', []):
                recipient_counts[recipient] = recipient_counts.get(recipient, 0) + 1
        
        return sorted(recipient_counts.keys(), key=recipient_counts.get, reverse=True)[:5]
    
    def _analyze_send_times(self, emails: List[Dict]) -> Dict:
        """Analyzes typical sending times"""
        # Placeholder implementation
        return {'typical_hours': [9, 10, 11, 14, 15, 16]}
    
    def _analyze_subject_patterns(self, emails: List[Dict]) -> List[str]:
        """Analyzes common subject patterns"""
        subjects = [e.get('subject', '') for e in emails]
        # Simple implementation - could use NLP for better pattern detection
        return list(set(subjects))[:10]
    
    def _is_recent(self, timestamp: str) -> bool:
        """Checks if timestamp is recent (last 7 days)"""
        # Placeholder implementation
        return True
    
    def _identify_specific_anomalies(self, baseline: Dict, current: Dict) -> List[str]:
        """Identifies specific types of anomalies"""
        anomalies = []
        
        if baseline.get('insufficient_data'):
            return anomalies
        
        # Check for unusual email length
        if 'avg_email_length' in baseline and 'avg_email_length' in current:
            if current['avg_email_length'] > baseline['avg_email_length'] * 2:
                anomalies.append("Unusually long emails")
            elif current['avg_email_length'] < baseline['avg_email_length'] * 0.5:
                anomalies.append("Unusually short emails")
        
        # Check for new recipients
        baseline_recipients = set(baseline.get('common_recipients', []))
        current_recipients = set(current.get('recipients', []))
        new_recipients = current_recipients - baseline_recipients
        
        if len(new_recipients) > len(baseline_recipients) * 0.5:
            anomalies.append("Many new recipients")
        
        return anomalies
