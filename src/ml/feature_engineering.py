"""Feature engineering for email analysis."""

import re
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import numpy as np
from collections import Counter
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import spacy

logger = logging.getLogger(__name__)

# Download required NLTK data
try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
except:
    logger.warning("Failed to download NLTK data")

# Load spaCy model
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    logger.warning("spaCy English model not found. Install with: python -m spacy download en_core_web_sm")
    nlp = None


class FeatureExtractor:
    """Extracts features from email data for ML models."""
    
    def __init__(self):
        self.urgent_keywords = [
            'urgent', 'immediate', 'asap', 'emergency', 'critical', 'important',
            'act now', 'limited time', 'expires', 'deadline', 'hurry', 'quick'
        ]
        
        self.suspicious_keywords = [
            'verify', 'confirm', 'update', 'suspend', 'locked', 'security',
            'click here', 'download', 'install', 'winner', 'congratulations',
            'free', 'prize', 'lottery', 'inheritance', 'tax refund'
        ]
        
        self.financial_keywords = [
            'bank', 'account', 'credit card', 'payment', 'transaction',
            'wire transfer', 'bitcoin', 'cryptocurrency', 'paypal', 'amazon'
        ]
        
        self.brand_keywords = [
            'microsoft', 'google', 'apple', 'amazon', 'paypal', 'ebay',
            'facebook', 'twitter', 'linkedin', 'netflix', 'spotify'
        ]
        
        try:
            self.stop_words = set(stopwords.words('english'))
        except:
            self.stop_words = set()
    
    def extract_content_features(self, email_data: Dict) -> Dict[str, Any]:
        """Extract content-based features from email."""
        features = {}
        
        # Get email content
        subject = email_data.get('subject', '')
        body_text = email_data.get('body_text', '')
        body_html = email_data.get('body_html', '')
        
        # Combine all text content
        full_text = f"{subject} {body_text} {body_html}".lower()
        
        # Basic text statistics
        features['text_length'] = len(full_text)
        features['word_count'] = len(full_text.split())
        features['sentence_count'] = len(re.split(r'[.!?]+', full_text))
        features['avg_word_length'] = np.mean([len(word) for word in full_text.split()]) if full_text.split() else 0
        
        # Keyword analysis
        features['urgent_words_count'] = sum(1 for keyword in self.urgent_keywords if keyword in full_text)
        features['suspicious_words_count'] = sum(1 for keyword in self.suspicious_keywords if keyword in full_text)
        features['financial_words_count'] = sum(1 for keyword in self.financial_keywords if keyword in full_text)
        features['brand_words_count'] = sum(1 for keyword in self.brand_keywords if keyword in full_text)
        
        # Spelling and grammar analysis
        features['spelling_errors'] = self._count_spelling_errors(full_text)
        features['grammar_errors'] = self._count_grammar_errors(full_text)
        
        # HTML analysis
        if body_html:
            features['html_tag_count'] = len(re.findall(r'<[^>]+>', body_html))
            features['hidden_text'] = 1 if 'display:none' in body_html or 'visibility:hidden' in body_html else 0
            features['suspicious_css'] = 1 if any(css in body_html for css in ['font-size:0', 'color:white']) else 0
        else:
            features['html_tag_count'] = 0
            features['hidden_text'] = 0
            features['suspicious_css'] = 0
        
        # Capitalization analysis
        features['all_caps_ratio'] = len(re.findall(r'[A-Z]{3,}', full_text)) / max(len(full_text.split()), 1)
        features['exclamation_count'] = full_text.count('!')
        features['question_count'] = full_text.count('?')
        
        # Sentiment analysis (basic)
        features['positive_words'] = self._count_positive_words(full_text)
        features['negative_words'] = self._count_negative_words(full_text)
        
        return features
    
    def extract_url_features(self, urls: List[str]) -> Dict[str, Any]:
        """Extract URL-based features."""
        features = {}
        
        if not urls:
            return {
                'url_count': 0,
                'avg_url_length': 0,
                'suspicious_domains': 0,
                'url_shorteners': 0,
                'ip_addresses': 0,
                'suspicious_tlds': 0,
                'url_redirects': 0
            }
        
        features['url_count'] = len(urls)
        
        url_lengths = []
        suspicious_domains = 0
        url_shorteners = 0
        ip_addresses = 0
        suspicious_tlds = 0
        
        shortener_domains = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
        ]
        
        suspicious_tld_list = [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download',
            '.zip', '.exe', '.scr', '.bat'
        ]
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                url_lengths.append(len(url))
                
                # Check for URL shorteners
                if any(shortener in domain for shortener in shortener_domains):
                    url_shorteners += 1
                
                # Check for IP addresses
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    ip_addresses += 1
                
                # Check for suspicious TLDs
                if any(tld in url.lower() for tld in suspicious_tld_list):
                    suspicious_tlds += 1
                
                # Check for suspicious domain patterns
                if self._is_suspicious_domain(domain):
                    suspicious_domains += 1
                    
            except Exception as e:
                logger.warning(f"Failed to parse URL {url}: {e}")
        
        features['avg_url_length'] = np.mean(url_lengths) if url_lengths else 0
        features['max_url_length'] = max(url_lengths) if url_lengths else 0
        features['suspicious_domains'] = suspicious_domains
        features['url_shorteners'] = url_shorteners
        features['ip_addresses'] = ip_addresses
        features['suspicious_tlds'] = suspicious_tlds
        features['url_redirects'] = 0  # Would need to check actual redirects
        
        return features
    
    def extract_header_features(self, headers: Dict) -> Dict[str, Any]:
        """Extract email header features."""
        features = {}
        
        # Authentication results
        features['spf_pass'] = 1 if headers.get('spf_result') == 'PASS' else 0
        features['dkim_pass'] = 1 if headers.get('dkim_result') == 'PASS' else 0
        features['dmarc_pass'] = 1 if headers.get('dmarc_result') == 'PASS' else 0
        
        # Sender reputation
        features['sender_reputation'] = headers.get('sender_reputation_score', 0.5)
        
        # Routing analysis
        features['hop_count'] = headers.get('hop_count', 0)
        features['suspicious_routing'] = 1 if headers.get('suspicious_routing') else 0
        features['timestamp_anomalies'] = 1 if headers.get('timestamp_anomalies') else 0
        
        # Geographic analysis
        sender_country = headers.get('sender_country', '')
        high_risk_countries = ['CN', 'RU', 'NG', 'PK', 'IN']  # Example list
        features['high_risk_country'] = 1 if sender_country in high_risk_countries else 0
        
        return features
    
    def extract_attachment_features(self, attachments: List[Dict]) -> Dict[str, Any]:
        """Extract attachment-based features."""
        features = {}
        
        if not attachments:
            return {
                'has_attachments': 0,
                'attachment_count': 0,
                'suspicious_extensions': 0,
                'executable_attachments': 0,
                'large_attachments': 0,
                'total_attachment_size': 0
            }
        
        features['has_attachments'] = 1
        features['attachment_count'] = len(attachments)
        
        suspicious_extensions = 0
        executable_attachments = 0
        large_attachments = 0
        total_size = 0
        
        suspicious_ext_list = [
            '.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.js',
            '.jar', '.zip', '.rar', '.7z', '.ace'
        ]
        
        executable_ext_list = [
            '.exe', '.scr', '.bat', '.cmd', '.pif', '.com', '.msi'
        ]
        
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            file_size = attachment.get('file_size', 0)
            
            total_size += file_size
            
            # Check for suspicious extensions
            if any(ext in filename for ext in suspicious_ext_list):
                suspicious_extensions += 1
            
            # Check for executable files
            if any(ext in filename for ext in executable_ext_list):
                executable_attachments += 1
            
            # Check for large files (>10MB)
            if file_size > 10 * 1024 * 1024:
                large_attachments += 1
        
        features['suspicious_extensions'] = suspicious_extensions
        features['executable_attachments'] = executable_attachments
        features['large_attachments'] = large_attachments
        features['total_attachment_size'] = total_size
        
        return features
    
    def extract_all_features(self, email_data: Dict) -> Dict[str, Any]:
        """Extract all features from email data."""
        features = {}
        
        # Content features
        content_features = self.extract_content_features(email_data)
        features.update(content_features)
        
        # URL features
        urls = email_data.get('urls', [])
        url_features = self.extract_url_features(urls)
        features.update(url_features)
        
        # Header features
        headers = email_data.get('headers', {})
        header_features = self.extract_header_features(headers)
        features.update(header_features)
        
        # Attachment features
        attachments = email_data.get('attachments', [])
        attachment_features = self.extract_attachment_features(attachments)
        features.update(attachment_features)
        
        return features
    
    def _count_spelling_errors(self, text: str) -> int:
        """Count potential spelling errors (basic implementation)."""
        # This is a simplified implementation
        # In production, you'd use a proper spell checker
        words = re.findall(r'\b[a-zA-Z]+\b', text)
        
        # Count words with unusual patterns
        error_count = 0
        for word in words:
            if len(word) > 2:
                # Check for repeated characters
                if re.search(r'(.)\1{2,}', word):
                    error_count += 1
                # Check for unusual character combinations
                if re.search(r'[qwxz]{2,}', word.lower()):
                    error_count += 1
        
        return error_count
    
    def _count_grammar_errors(self, text: str) -> int:
        """Count potential grammar errors (basic implementation)."""
        # Simplified grammar error detection
        error_count = 0
        
        # Check for common patterns
        if re.search(r'\b(your|you\'re)\s+(welcome|wellcome)\b', text.lower()):
            error_count += 1
        if re.search(r'\b(there|their|they\'re)\s+(are|is)\b', text.lower()):
            error_count += 1
        
        return error_count
    
    def _count_positive_words(self, text: str) -> int:
        """Count positive sentiment words."""
        positive_words = [
            'great', 'excellent', 'amazing', 'wonderful', 'fantastic',
            'congratulations', 'winner', 'success', 'benefit', 'reward'
        ]
        return sum(1 for word in positive_words if word in text.lower())
    
    def _count_negative_words(self, text: str) -> int:
        """Count negative sentiment words."""
        negative_words = [
            'urgent', 'problem', 'issue', 'error', 'suspended', 'locked',
            'expired', 'failed', 'denied', 'blocked', 'warning', 'alert'
        ]
        return sum(1 for word in negative_words if word in text.lower())
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain appears suspicious."""
        # Check for typosquatting patterns
        legitimate_domains = [
            'microsoft.com', 'google.com', 'amazon.com', 'paypal.com',
            'apple.com', 'facebook.com', 'twitter.com', 'linkedin.com'
        ]
        
        for legit_domain in legitimate_domains:
            # Check for character substitution
            if self._calculate_domain_similarity(domain, legit_domain) > 0.8:
                return True
        
        # Check for suspicious patterns
        if re.search(r'\d+', domain):  # Numbers in domain
            return True
        if len(domain.split('.')) > 3:  # Too many subdomains
            return True
        if '-' in domain and domain.count('-') > 2:  # Too many hyphens
            return True
        
        return False
    
    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains."""
        # Simple Levenshtein distance-based similarity
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
        
        distance = levenshtein_distance(domain1, domain2)
        max_len = max(len(domain1), len(domain2))
        return 1 - (distance / max_len) if max_len > 0 else 0
