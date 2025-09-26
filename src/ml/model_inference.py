"""Real-time prediction engine for phishing detection."""

import logging
import pickle
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import asyncio

try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

from .data_loader import DataLoader
from .feature_engineering import FeatureExtractor
from ..utils.config import settings

logger = logging.getLogger(__name__)


class ModelInference:
    """Real-time inference engine for phishing detection."""
    
    def __init__(self, model_dir: str = "data/models"):
        self.model_dir = Path(model_dir)
        self.models = {}
        self.model_metadata = {}
        self.data_loader = DataLoader()
        self.feature_extractor = FeatureExtractor()
        
        # Load models and preprocessors
        self._load_models()
        self._load_preprocessors()
    
    def _load_models(self):
        """Load all trained models."""
        model_files = {
            'random_forest': 'random_forest.pkl',
            'svm': 'svm_model.pkl',
            'ensemble': 'ensemble_model.pkl'
        }
        
        for model_name, filename in model_files.items():
            model_path = self.model_dir / filename
            if model_path.exists():
                try:
                    with open(model_path, "rb") as f:
                        self.models[model_name] = pickle.load(f)
                    logger.info(f"Loaded {model_name} model")
                except Exception as e:
                    logger.error(f"Failed to load {model_name} model: {e}")
        
        # Load deep learning model
        if TENSORFLOW_AVAILABLE:
            dl_model_path = self.model_dir / "deep_learning.h5"
            if dl_model_path.exists():
                try:
                    self.models['deep_learning'] = tf.keras.models.load_model(dl_model_path)
                    logger.info("Loaded deep learning model")
                except Exception as e:
                    logger.error(f"Failed to load deep learning model: {e}")
        
        # Load model metadata
        metadata_path = self.model_dir / "training_results.json"
        if metadata_path.exists():
            try:
                with open(metadata_path, "r") as f:
                    self.model_metadata = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load model metadata: {e}")
    
    def _load_preprocessors(self):
        """Load preprocessing objects."""
        success = self.data_loader.load_preprocessors(str(self.model_dir))
        if not success:
            logger.warning("Failed to load preprocessors, using defaults")
    
    async def predict_single_email(self, email_data: Dict) -> Dict[str, Any]:
        """Predict phishing probability for a single email."""
        try:
            # Extract features
            features = self.feature_extractor.extract_all_features(email_data)
            
            # Prepare features for prediction
            X_sample = self.data_loader.prepare_single_sample(features)
            
            # Get predictions from all models
            predictions = {}
            prediction_times = {}
            
            for model_name, model in self.models.items():
                start_time = asyncio.get_event_loop().time()
                
                try:
                    if model_name == 'deep_learning' and TENSORFLOW_AVAILABLE:
                        pred_proba = model.predict(X_sample, verbose=0)[0][0]
                        pred_class = int(pred_proba > 0.5)
                    else:
                        pred_class = model.predict(X_sample)[0]
                        pred_proba = model.predict_proba(X_sample)[0][1]
                    
                    predictions[model_name] = {
                        'probability': float(pred_proba),
                        'prediction': int(pred_class),
                        'confidence': abs(pred_proba - 0.5) * 2  # Convert to 0-1 scale
                    }
                    
                    prediction_times[model_name] = asyncio.get_event_loop().time() - start_time
                    
                except Exception as e:
                    logger.error(f"Prediction failed for {model_name}: {e}")
                    predictions[model_name] = {
                        'probability': 0.5,
                        'prediction': 0,
                        'confidence': 0.0,
                        'error': str(e)
                    }
            
            # Calculate ensemble prediction
            ensemble_result = self._calculate_ensemble_prediction(predictions)
            
            # Determine threat level
            threat_level = self._determine_threat_level(ensemble_result['probability'])
            
            # Create comprehensive result
            result = {
                'overall_threat_score': ensemble_result['probability'],
                'is_phishing': ensemble_result['prediction'],
                'confidence_level': threat_level,
                'threat_category': self._classify_threat_category(features, ensemble_result['probability']),
                'individual_predictions': predictions,
                'ensemble_prediction': ensemble_result,
                'features_used': features,
                'prediction_times': prediction_times,
                'model_versions': self._get_model_versions()
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Email prediction failed: {e}")
            return {
                'overall_threat_score': 0.5,
                'is_phishing': False,
                'confidence_level': 'LOW',
                'threat_category': 'UNKNOWN',
                'error': str(e)
            }
    
    async def predict_batch(self, email_batch: List[Dict]) -> List[Dict[str, Any]]:
        """Predict phishing probability for a batch of emails."""
        results = []
        
        for email_data in email_batch:
            result = await self.predict_single_email(email_data)
            results.append(result)
        
        return results
    
    def _calculate_ensemble_prediction(self, predictions: Dict[str, Dict]) -> Dict[str, Any]:
        """Calculate weighted ensemble prediction."""
        # Default weights from settings
        try:
            weights = settings.ensemble_weights
        except:
            weights = [0.3, 0.3, 0.4]  # Default weights
        
        # Model priority order
        model_priority = ['ensemble', 'random_forest', 'svm', 'deep_learning']
        
        # Get available models in priority order
        available_models = [m for m in model_priority if m in predictions and 'error' not in predictions[m]]
        
        if not available_models:
            return {'probability': 0.5, 'prediction': 0, 'confidence': 0.0}
        
        # Use ensemble model if available
        if 'ensemble' in available_models:
            ensemble_pred = predictions['ensemble']
            return {
                'probability': ensemble_pred['probability'],
                'prediction': ensemble_pred['prediction'],
                'confidence': ensemble_pred['confidence'],
                'method': 'ensemble_model'
            }
        
        # Otherwise, calculate weighted average
        total_weight = 0
        weighted_prob = 0
        
        for i, model_name in enumerate(available_models[:len(weights)]):
            weight = weights[i] if i < len(weights) else weights[-1]
            prob = predictions[model_name]['probability']
            
            weighted_prob += prob * weight
            total_weight += weight
        
        if total_weight > 0:
            final_prob = weighted_prob / total_weight
        else:
            final_prob = 0.5
        
        return {
            'probability': final_prob,
            'prediction': int(final_prob > settings.confidence_threshold),
            'confidence': abs(final_prob - 0.5) * 2,
            'method': 'weighted_average',
            'models_used': available_models
        }
    
    def _determine_threat_level(self, probability: float) -> str:
        """Determine threat level based on probability."""
        if probability >= 0.9:
            return 'CRITICAL'
        elif probability >= 0.7:
            return 'HIGH'
        elif probability >= 0.5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _classify_threat_category(self, features: Dict, probability: float) -> str:
        """Classify the type of threat based on features."""
        if probability < 0.5:
            return 'LEGITIMATE'
        
        # Analyze features to determine threat type
        if features.get('financial_words_count', 0) > 2:
            return 'FINANCIAL_SCAM'
        elif features.get('urgent_words_count', 0) > 3:
            return 'PHISHING'
        elif features.get('suspicious_extensions', 0) > 0:
            return 'MALWARE'
        elif features.get('suspicious_domains', 0) > 0:
            return 'PHISHING'
        else:
            return 'SPAM'
    
    def _get_model_versions(self) -> Dict[str, str]:
        """Get version information for loaded models."""
        versions = {}
        
        for model_name in self.models.keys():
            if model_name in self.model_metadata:
                # Extract version from metadata if available
                versions[model_name] = "v1.0"  # Placeholder
            else:
                versions[model_name] = "unknown"
        
        return versions
    
    def get_model_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded models."""
        stats = {
            'loaded_models': list(self.models.keys()),
            'model_count': len(self.models),
            'preprocessors_loaded': bool(self.data_loader.scaler),
            'feature_count': len(self.data_loader.feature_columns) if self.data_loader.feature_columns else 0
        }
        
        # Add performance metrics if available
        if self.model_metadata:
            stats['performance_metrics'] = {}
            for model_name, metadata in self.model_metadata.items():
                if isinstance(metadata, dict) and 'accuracy' in metadata:
                    stats['performance_metrics'][model_name] = {
                        'accuracy': metadata.get('accuracy'),
                        'f1_score': metadata.get('f1_score'),
                        'precision': metadata.get('precision'),
                        'recall': metadata.get('recall')
                    }
        
        return stats
    
    def reload_models(self):
        """Reload all models and preprocessors."""
        logger.info("Reloading models...")
        self.models.clear()
        self.model_metadata.clear()
        
        self._load_models()
        self._load_preprocessors()
        
        logger.info(f"Reloaded {len(self.models)} models")
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the inference system."""
        health_status = {
            'status': 'healthy',
            'models_loaded': len(self.models),
            'models_available': list(self.models.keys()),
            'preprocessors_ready': bool(self.data_loader.scaler),
            'issues': []
        }
        
        # Test each model with dummy data
        dummy_features = {
            'text_length': 100,
            'word_count': 20,
            'urgent_words_count': 1,
            'suspicious_links_count': 0,
            'url_count': 1,
            'has_attachments': 0,
            'spf_pass': 1,
            'sender_reputation': 0.8
        }
        
        try:
            test_result = await self.predict_single_email({'features': dummy_features})
            if 'error' in test_result:
                health_status['issues'].append(f"Prediction test failed: {test_result['error']}")
                health_status['status'] = 'degraded'
        except Exception as e:
            health_status['issues'].append(f"Health check prediction failed: {e}")
            health_status['status'] = 'unhealthy'
        
        return health_status
