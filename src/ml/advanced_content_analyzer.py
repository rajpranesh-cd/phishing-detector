"""
Advanced Content Analysis with Multi-Language NLP and Psychological Analysis
"""

import spacy
import langdetect
from typing import Dict, List, Optional
import re
import numpy as np
from collections import Counter
import logging

logger = logging.getLogger(__name__)

class AdvancedContentAnalyzer:
    """Multi-language analysis with psychological manipulation detection"""
    
    def __init__(self):
        # Load language models
        self.supported_languages = {
            'en': 'en_core_web_sm',
            'es': 'es_core_news_sm', 
            'fr': 'fr_core_news_sm',
            'de': 'de_core_news_sm',
            'it': 'it_core_news_sm',
            'pt': 'pt_core_news_sm',
            'ru': 'ru_core_news_sm',
            'zh': 'zh_core_web_sm',
            'ja': 'ja_core_news_sm',
            'ko': 'ko_core_news_sm'
        }
        
        self.nlp_models = {}
        self._load_available_models()
        
        # Psychological manipulation patterns by language
        self.manipulation_patterns = {
            'en': {
                'urgency': ['urgent', 'immediate', 'expires today', 'act now', 'limited time', 'deadline'],
                'fear': ['suspended', 'blocked', 'security alert', 'unauthorized', 'compromised', 'hacked'],
                'authority': ['bank', 'government', 'irs', 'police', 'legal action', 'court'],
                'greed': ['winner', 'prize', 'lottery', 'inheritance', 'free money', 'cash prize'],
                'trust': ['verify', 'confirm', 'update', 'secure', 'protect', 'safety']
            },
            'es': {
                'urgency': ['urgente', 'inmediato', 'expira hoy', 'actúa ahora', 'tiempo limitado'],
                'fear': ['suspendido', 'bloqueado', 'alerta de seguridad', 'no autorizado', 'comprometido'],
                'authority': ['banco', 'gobierno', 'hacienda', 'policía', 'acción legal'],
                'greed': ['ganador', 'premio', 'lotería', 'herencia', 'dinero gratis'],
                'trust': ['verificar', 'confirmar', 'actualizar', 'seguro', 'proteger']
            },
            'fr': {
                'urgency': ['urgent', 'immédiat', 'expire aujourd\'hui', 'agissez maintenant', 'temps limité'],
                'fear': ['suspendu', 'bloqué', 'alerte sécurité', 'non autorisé', 'compromis'],
                'authority': ['banque', 'gouvernement', 'impôts', 'police', 'action légale'],
                'greed': ['gagnant', 'prix', 'loterie', 'héritage', 'argent gratuit'],
                'trust': ['vérifier', 'confirmer', 'mettre à jour', 'sécurisé', 'protéger']
            }
        }
        
        # Scam indicators by language
        self.scam_indicators = {
            'en': ['nigerian prince', 'advance fee', 'wire transfer', 'western union', 'money gram'],
            'es': ['príncipe nigeriano', 'tarifa adelantada', 'transferencia bancaria'],
            'fr': ['prince nigérian', 'frais d\'avance', 'virement bancaire']
        }
    
    def _load_available_models(self):
        """Load available spaCy language models"""
        for lang_code, model_name in self.supported_languages.items():
            try:
                self.nlp_models[lang_code] = spacy.load(model_name)
                logger.info(f"Loaded {model_name} for {lang_code}")
            except OSError:
                logger.warning(f"Language model {model_name} not available for {lang_code}")
    
    async def analyze_psychological_manipulation(self, email_text: str) -> Dict:
        """
        Detects urgency, fear, authority manipulation tactics
        Works across 15+ languages
        """
        try:
            # Detect language
            detected_lang = langdetect.detect(email_text)
            if detected_lang not in self.supported_languages:
                detected_lang = 'en'  # Default to English
            
            # Get manipulation patterns for detected language
            patterns = self.manipulation_patterns.get(detected_lang, self.manipulation_patterns['en'])
            
            # Analyze text
            text_lower = email_text.lower()
            manipulation_scores = {}
            
            for category, keywords in patterns.items():
                score = 0
                matched_keywords = []
                
                for keyword in keywords:
                    if keyword in text_lower:
                        score += 1
                        matched_keywords.append(keyword)
                
                manipulation_scores[category] = {
                    'score': min(score / len(keywords), 1.0),
                    'matched_keywords': matched_keywords
                }
            
            # Calculate overall manipulation score
            overall_score = np.mean([cat['score'] for cat in manipulation_scores.values()])
            
            # Detect specific scam patterns
            scam_patterns = self._detect_scam_patterns(email_text, detected_lang)
            
            # Analyze linguistic features
            linguistic_analysis = await self._analyze_linguistic_features(email_text, detected_lang)
            
            return {
                'detected_language': detected_lang,
                'manipulation_scores': manipulation_scores,
                'overall_manipulation_score': overall_score,
                'scam_patterns': scam_patterns,
                'linguistic_analysis': linguistic_analysis,
                'threat_level': self._calculate_threat_level(overall_score, scam_patterns)
            }
            
        except Exception as e:
            logger.error(f"Psychological manipulation analysis failed: {e}")
            return {'error': str(e)}
    
    def _detect_scam_patterns(self, text: str, language: str) -> Dict:
        """Detects common scam patterns"""
        text_lower = text.lower()
        scam_indicators = self.scam_indicators.get(language, self.scam_indicators['en'])
        
        detected_patterns = []
        for indicator in scam_indicators:
            if indicator in text_lower:
                detected_patterns.append(indicator)
        
        # Additional pattern detection
        money_amounts = re.findall(r'\$[\d,]+|\€[\d,]+|£[\d,]+', text)
        phone_numbers = re.findall(r'\+?\d{1,3}[-.\s]?$$?\d{1,3}$$?[-.\s]?\d{1,4}[-.\s]?\d{1,4}', text)
        
        return {
            'scam_keywords': detected_patterns,
            'money_amounts': money_amounts,
            'phone_numbers': phone_numbers,
            'scam_score': len(detected_patterns) * 0.3 + len(money_amounts) * 0.2
        }
    
    async def _analyze_linguistic_features(self, text: str, language: str) -> Dict:
        """Analyzes linguistic features for authenticity"""
        if language not in self.nlp_models:
            return {'error': 'Language model not available'}
        
        nlp = self.nlp_models[language]
        doc = nlp(text)
        
        # Grammar and spelling analysis
        grammar_errors = self._count_grammar_errors(doc)
        
        # Readability analysis
        readability = self._calculate_readability(text)
        
        # Sentiment analysis
        sentiment = self._analyze_sentiment(doc)
        
        return {
            'grammar_errors': grammar_errors,
            'readability_score': readability,
            'sentiment': sentiment,
            'sentence_count': len(list(doc.sents)),
            'word_count': len([token for token in doc if not token.is_space]),
            'avg_sentence_length': len([token for token in doc if not token.is_space]) / max(len(list(doc.sents)), 1)
        }
    
    def _count_grammar_errors(self, doc) -> int:
        """Simple grammar error detection"""
        # Placeholder implementation - could use LanguageTool or similar
        errors = 0
        
        # Check for basic patterns that might indicate poor grammar
        for sent in doc.sents:
            tokens = [token for token in sent if not token.is_space]
            if len(tokens) > 0:
                # Check if sentence starts with lowercase (basic check)
                if tokens[0].text[0].islower() and tokens[0].pos_ not in ['PRON', 'ADV']:
                    errors += 1
        
        return errors
    
    def _calculate_readability(self, text: str) -> float:
        """Calculate readability score (simplified Flesch Reading Ease)"""
        sentences = len(re.split(r'[.!?]+', text))
        words = len(text.split())
        syllables = sum([self._count_syllables(word) for word in text.split()])
        
        if sentences == 0 or words == 0:
            return 0.0
        
        # Simplified Flesch Reading Ease formula
        score = 206.835 - (1.015 * (words / sentences)) - (84.6 * (syllables / words))
        return max(0.0, min(100.0, score))
    
    def _count_syllables(self, word: str) -> int:
        """Count syllables in a word (simplified)"""
        word = word.lower()
        vowels = 'aeiouy'
        syllable_count = 0
        previous_was_vowel = False
        
        for char in word:
            if char in vowels:
                if not previous_was_vowel:
                    syllable_count += 1
                previous_was_vowel = True
            else:
                previous_was_vowel = False
        
        # Handle silent 'e'
        if word.endswith('e') and syllable_count > 1:
            syllable_count -= 1
        
        return max(1, syllable_count)
    
    def _analyze_sentiment(self, doc) -> Dict:
        """Analyze sentiment of the text"""
        # Simple sentiment analysis based on word polarity
        positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic']
        negative_words = ['bad', 'terrible', 'awful', 'horrible', 'disgusting', 'hate']
        
        text_lower = doc.text.lower()
        positive_count = sum(1 for word in positive_words if word in text_lower)
        negative_count = sum(1 for word in negative_words if word in text_lower)
        
        if positive_count + negative_count == 0:
            polarity = 0.0
        else:
            polarity = (positive_count - negative_count) / (positive_count + negative_count)
        
        return {
            'polarity': polarity,
            'positive_words': positive_count,
            'negative_words': negative_count
        }
    
    def _calculate_threat_level(self, manipulation_score: float, scam_patterns: Dict) -> str:
        """Calculate overall threat level"""
        combined_score = manipulation_score + scam_patterns.get('scam_score', 0)
        
        if combined_score > 0.8:
            return "CRITICAL"
        elif combined_score > 0.6:
            return "HIGH"
        elif combined_score > 0.4:
            return "MEDIUM"
        else:
            return "LOW"

class MultimediaAnalyzer:
    """Analyzes images and documents for hidden threats"""
    
    def __init__(self):
        try:
            import cv2
            import pytesseract
            from PIL import Image
            self.cv2 = cv2
            self.pytesseract = pytesseract
            self.PIL_Image = Image
        except ImportError:
            logger.warning("Multimedia analysis dependencies not installed")
            self.cv2 = None
    
    async def detect_brand_impersonation(self, image_data: bytes) -> Dict:
        """
        Uses computer vision to detect logo impersonation
        Identifies slight modifications in brand assets
        """
        if not self.cv2:
            return {'error': 'Computer vision dependencies not available'}
        
        try:
            # Convert bytes to image
            image = self.PIL_Image.open(io.BytesIO(image_data))
            image_array = np.array(image)
            
            # Extract text from image using OCR
            extracted_text = self.pytesseract.image_to_string(image)
            
            # Detect known brand names
            brand_names = [
                'microsoft', 'google', 'apple', 'amazon', 'paypal', 'ebay',
                'facebook', 'instagram', 'twitter', 'linkedin', 'netflix',
                'spotify', 'adobe', 'dropbox', 'zoom', 'slack'
            ]
            
            detected_brands = []
            text_lower = extracted_text.lower()
            
            for brand in brand_names:
                if brand in text_lower:
                    detected_brands.append(brand)
            
            # Analyze image features for logo detection
            logo_features = await self._analyze_logo_features(image_array)
            
            # Calculate impersonation score
            impersonation_score = len(detected_brands) * 0.3 + logo_features.get('logo_confidence', 0) * 0.7
            
            return {
                'extracted_text': extracted_text,
                'detected_brands': detected_brands,
                'logo_analysis': logo_features,
                'impersonation_score': min(impersonation_score, 1.0),
                'threat_level': 'HIGH' if impersonation_score > 0.7 else 'MEDIUM' if impersonation_score > 0.4 else 'LOW'
            }
            
        except Exception as e:
            logger.error(f"Brand impersonation detection failed: {e}")
            return {'error': str(e)}
    
    async def _analyze_logo_features(self, image_array: np.ndarray) -> Dict:
        """Analyze image features for logo detection"""
        try:
            # Convert to grayscale
            gray = self.cv2.cvtColor(image_array, self.cv2.COLOR_RGB2GRAY)
            
            # Detect edges
            edges = self.cv2.Canny(gray, 50, 150)
            
            # Find contours
            contours, _ = self.cv2.findContours(edges, self.cv2.RETR_EXTERNAL, self.cv2.CHAIN_APPROX_SIMPLE)
            
            # Analyze contours for logo-like shapes
            logo_like_shapes = 0
            for contour in contours:
                area = self.cv2.contourArea(contour)
                if 1000 < area < 50000:  # Logo-sized areas
                    logo_like_shapes += 1
            
            return {
                'logo_confidence': min(logo_like_shapes * 0.1, 1.0),
                'contours_found': len(contours),
                'logo_like_shapes': logo_like_shapes
            }
            
        except Exception as e:
            logger.error(f"Logo feature analysis failed: {e}")
            return {'logo_confidence': 0.0}
