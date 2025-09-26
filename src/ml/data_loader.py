"""Dataset loading and preprocessing for ML models."""

import asyncio
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import pickle

logger = logging.getLogger(__name__)


class DataLoader:
    """Handles loading and preprocessing of phishing detection datasets."""
    
    def __init__(self, data_dir: str = "data/datasets"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        
    def create_sample_dataset(self) -> pd.DataFrame:
        """Create a sample dataset for development and testing."""
        np.random.seed(42)
        
        # Generate synthetic phishing email features
        n_samples = 10000
        
        # Content features
        urgent_words_count = np.random.poisson(2, n_samples)
        suspicious_links_count = np.random.poisson(1, n_samples)
        spelling_errors = np.random.poisson(3, n_samples)
        
        # URL features
        url_length = np.random.normal(50, 20, n_samples)
        suspicious_domains = np.random.binomial(1, 0.3, n_samples)
        url_shorteners = np.random.binomial(1, 0.2, n_samples)
        
        # Header features
        spf_pass = np.random.binomial(1, 0.7, n_samples)
        dkim_pass = np.random.binomial(1, 0.6, n_samples)
        sender_reputation = np.random.uniform(0, 1, n_samples)
        
        # Attachment features
        has_attachments = np.random.binomial(1, 0.4, n_samples)
        suspicious_extensions = np.random.binomial(1, 0.1, n_samples)
        
        # Create labels (1 = phishing, 0 = legitimate)
        # Higher scores for features indicate higher phishing probability
        phishing_score = (
            urgent_words_count * 0.2 +
            suspicious_links_count * 0.3 +
            spelling_errors * 0.1 +
            (url_length > 80) * 0.2 +
            suspicious_domains * 0.4 +
            url_shorteners * 0.3 +
            (1 - spf_pass) * 0.2 +
            (1 - dkim_pass) * 0.2 +
            (1 - sender_reputation) * 0.3 +
            suspicious_extensions * 0.5
        )
        
        # Add noise and create binary labels
        phishing_score += np.random.normal(0, 0.5, n_samples)
        is_phishing = (phishing_score > 1.5).astype(int)
        
        # Create DataFrame
        data = pd.DataFrame({
            'urgent_words_count': urgent_words_count,
            'suspicious_links_count': suspicious_links_count,
            'spelling_errors': spelling_errors,
            'url_length': url_length,
            'suspicious_domains': suspicious_domains,
            'url_shorteners': url_shorteners,
            'spf_pass': spf_pass,
            'dkim_pass': dkim_pass,
            'sender_reputation': sender_reputation,
            'has_attachments': has_attachments,
            'suspicious_extensions': suspicious_extensions,
            'is_phishing': is_phishing
        })
        
        return data
    
    def load_dataset(self, dataset_name: str = "phishing_dataset.csv") -> Optional[pd.DataFrame]:
        """Load dataset from file or create sample if not exists."""
        dataset_path = self.data_dir / dataset_name
        
        try:
            if dataset_path.exists():
                logger.info(f"Loading dataset from {dataset_path}")
                return pd.read_csv(dataset_path)
            else:
                logger.info("Dataset not found, creating sample dataset")
                sample_data = self.create_sample_dataset()
                sample_data.to_csv(dataset_path, index=False)
                logger.info(f"Sample dataset saved to {dataset_path}")
                return sample_data
                
        except Exception as e:
            logger.error(f"Failed to load dataset: {e}")
            return None
    
    def preprocess_features(self, data: pd.DataFrame, 
                          fit_scalers: bool = True) -> Tuple[np.ndarray, np.ndarray]:
        """Preprocess features for ML models."""
        try:
            # Separate features and labels
            feature_columns = [col for col in data.columns if col != 'is_phishing']
            X = data[feature_columns].copy()
            y = data['is_phishing'].values
            
            # Handle missing values
            X = X.fillna(X.mean())
            
            # Store feature columns for later use
            if fit_scalers:
                self.feature_columns = feature_columns
            
            # Scale numerical features
            numerical_features = X.select_dtypes(include=[np.number]).columns
            if fit_scalers:
                X[numerical_features] = self.scaler.fit_transform(X[numerical_features])
            else:
                X[numerical_features] = self.scaler.transform(X[numerical_features])
            
            # Encode categorical features (if any)
            categorical_features = X.select_dtypes(include=['object']).columns
            for col in categorical_features:
                if fit_scalers:
                    X[col] = self.label_encoder.fit_transform(X[col].astype(str))
                else:
                    # Handle unseen categories
                    X[col] = X[col].astype(str)
                    known_categories = set(self.label_encoder.classes_)
                    X[col] = X[col].apply(lambda x: x if x in known_categories else 'unknown')
                    X[col] = self.label_encoder.transform(X[col])
            
            return X.values, y
            
        except Exception as e:
            logger.error(f"Feature preprocessing failed: {e}")
            raise
    
    def split_dataset(self, X: np.ndarray, y: np.ndarray, 
                     test_size: float = 0.2, val_size: float = 0.1) -> Tuple:
        """Split dataset into train, validation, and test sets."""
        # First split: train+val vs test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Second split: train vs val
        val_size_adjusted = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_size_adjusted, random_state=42, stratify=y_temp
        )
        
        logger.info(f"Dataset split - Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def save_preprocessors(self, model_dir: str = "data/models"):
        """Save preprocessing objects."""
        model_path = Path(model_dir)
        model_path.mkdir(parents=True, exist_ok=True)
        
        try:
            # Save scaler
            with open(model_path / "scaler.pkl", "wb") as f:
                pickle.dump(self.scaler, f)
            
            # Save label encoder
            with open(model_path / "label_encoder.pkl", "wb") as f:
                pickle.dump(self.label_encoder, f)
            
            # Save feature columns
            with open(model_path / "feature_columns.pkl", "wb") as f:
                pickle.dump(self.feature_columns, f)
            
            logger.info("Preprocessing objects saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save preprocessors: {e}")
    
    def load_preprocessors(self, model_dir: str = "data/models"):
        """Load preprocessing objects."""
        model_path = Path(model_dir)
        
        try:
            # Load scaler
            with open(model_path / "scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)
            
            # Load label encoder
            with open(model_path / "label_encoder.pkl", "rb") as f:
                self.label_encoder = pickle.load(f)
            
            # Load feature columns
            with open(model_path / "feature_columns.pkl", "rb") as f:
                self.feature_columns = pickle.load(f)
            
            logger.info("Preprocessing objects loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load preprocessors: {e}")
            return False
    
    def prepare_single_sample(self, features: Dict) -> np.ndarray:
        """Prepare a single sample for prediction."""
        try:
            # Create DataFrame with single row
            sample_df = pd.DataFrame([features])
            
            # Ensure all required columns are present
            for col in self.feature_columns:
                if col not in sample_df.columns:
                    sample_df[col] = 0  # Default value for missing features
            
            # Reorder columns to match training data
            sample_df = sample_df[self.feature_columns]
            
            # Preprocess (don't fit scalers)
            X_sample, _ = self.preprocess_features(sample_df, fit_scalers=False)
            
            return X_sample
            
        except Exception as e:
            logger.error(f"Failed to prepare sample: {e}")
            raise
