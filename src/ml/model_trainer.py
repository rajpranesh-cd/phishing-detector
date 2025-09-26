"""Machine learning model training pipeline."""

import logging
import pickle
import json
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd
from datetime import datetime

# Scikit-learn imports
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import cross_val_score, GridSearchCV

# Deep learning imports
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
    from tensorflow.keras.optimizers import Adam
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logger.warning("TensorFlow not available. Deep learning models will be disabled.")

from .data_loader import DataLoader
from ..utils.database import db_manager

logger = logging.getLogger(__name__)


class ModelTrainer:
    """Trains and evaluates ML models for phishing detection."""
    
    def __init__(self, model_dir: str = "data/models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.data_loader = DataLoader()
        self.models = {}
        self.model_metrics = {}
        
    def train_random_forest(self, X_train: np.ndarray, y_train: np.ndarray,
                          X_val: np.ndarray, y_val: np.ndarray) -> Dict[str, Any]:
        """Train Random Forest classifier."""
        logger.info("Training Random Forest model...")
        
        # Hyperparameter tuning
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        rf = RandomForestClassifier(random_state=42, n_jobs=-1)
        
        # Grid search with cross-validation
        grid_search = GridSearchCV(
            rf, param_grid, cv=5, scoring='f1', n_jobs=-1, verbose=1
        )
        grid_search.fit(X_train, y_train)
        
        # Best model
        best_rf = grid_search.best_estimator_
        
        # Predictions
        y_pred = best_rf.predict(X_val)
        y_pred_proba = best_rf.predict_proba(X_val)[:, 1]
        
        # Metrics
        metrics = self._calculate_metrics(y_val, y_pred, y_pred_proba)
        metrics['best_params'] = grid_search.best_params_
        
        # Feature importance
        feature_importance = best_rf.feature_importances_
        metrics['feature_importance'] = feature_importance.tolist()
        
        # Save model
        model_path = self.model_dir / "random_forest.pkl"
        with open(model_path, "wb") as f:
            pickle.dump(best_rf, f)
        
        self.models['random_forest'] = best_rf
        self.model_metrics['random_forest'] = metrics
        
        logger.info(f"Random Forest - Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1_score']:.4f}")
        
        return metrics
    
    def train_svm(self, X_train: np.ndarray, y_train: np.ndarray,
                  X_val: np.ndarray, y_val: np.ndarray) -> Dict[str, Any]:
        """Train SVM classifier."""
        logger.info("Training SVM model...")
        
        # Hyperparameter tuning
        param_grid = {
            'C': [0.1, 1, 10, 100],
            'gamma': ['scale', 'auto', 0.001, 0.01, 0.1, 1],
            'kernel': ['rbf', 'linear']
        }
        
        svm = SVC(random_state=42, probability=True)
        
        # Grid search with cross-validation
        grid_search = GridSearchCV(
            svm, param_grid, cv=5, scoring='f1', n_jobs=-1, verbose=1
        )
        grid_search.fit(X_train, y_train)
        
        # Best model
        best_svm = grid_search.best_estimator_
        
        # Predictions
        y_pred = best_svm.predict(X_val)
        y_pred_proba = best_svm.predict_proba(X_val)[:, 1]
        
        # Metrics
        metrics = self._calculate_metrics(y_val, y_pred, y_pred_proba)
        metrics['best_params'] = grid_search.best_params_
        
        # Save model
        model_path = self.model_dir / "svm_model.pkl"
        with open(model_path, "wb") as f:
            pickle.dump(best_svm, f)
        
        self.models['svm'] = best_svm
        self.model_metrics['svm'] = metrics
        
        logger.info(f"SVM - Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1_score']:.4f}")
        
        return metrics
    
    def train_deep_learning(self, X_train: np.ndarray, y_train: np.ndarray,
                          X_val: np.ndarray, y_val: np.ndarray) -> Dict[str, Any]:
        """Train deep learning model."""
        if not TENSORFLOW_AVAILABLE:
            logger.warning("TensorFlow not available, skipping deep learning model")
            return {}
        
        logger.info("Training Deep Learning model...")
        
        # Build model architecture
        model = Sequential([
            Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(64, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(32, activation='relu'),
            BatchNormalization(),
            Dropout(0.2),
            
            Dense(16, activation='relu'),
            Dropout(0.2),
            
            Dense(1, activation='sigmoid')
        ])
        
        # Compile model
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        # Callbacks
        callbacks = [
            EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True),
            ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5, min_lr=1e-7)
        ]
        
        # Train model
        history = model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=100,
            batch_size=32,
            callbacks=callbacks,
            verbose=1
        )
        
        # Predictions
        y_pred_proba = model.predict(X_val).flatten()
        y_pred = (y_pred_proba > 0.5).astype(int)
        
        # Metrics
        metrics = self._calculate_metrics(y_val, y_pred, y_pred_proba)
        metrics['training_history'] = {
            'loss': history.history['loss'],
            'val_loss': history.history['val_loss'],
            'accuracy': history.history['accuracy'],
            'val_accuracy': history.history['val_accuracy']
        }
        
        # Save model
        model_path = self.model_dir / "deep_learning.h5"
        model.save(model_path)
        
        self.models['deep_learning'] = model
        self.model_metrics['deep_learning'] = metrics
        
        logger.info(f"Deep Learning - Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1_score']:.4f}")
        
        return metrics
    
    def create_ensemble_model(self, X_train: np.ndarray, y_train: np.ndarray,
                            X_val: np.ndarray, y_val: np.ndarray) -> Dict[str, Any]:
        """Create ensemble model combining multiple classifiers."""
        logger.info("Creating ensemble model...")
        
        # Ensure we have trained models
        if 'random_forest' not in self.models or 'svm' not in self.models:
            raise ValueError("Random Forest and SVM models must be trained first")
        
        # Create voting classifier
        estimators = [
            ('rf', self.models['random_forest']),
            ('svm', self.models['svm'])
        ]
        
        # Add logistic regression as a simple baseline
        lr = LogisticRegression(random_state=42, max_iter=1000)
        lr.fit(X_train, y_train)
        estimators.append(('lr', lr))
        
        # Create ensemble
        ensemble = VotingClassifier(
            estimators=estimators,
            voting='soft'  # Use probability-based voting
        )
        
        ensemble.fit(X_train, y_train)
        
        # Predictions
        y_pred = ensemble.predict(X_val)
        y_pred_proba = ensemble.predict_proba(X_val)[:, 1]
        
        # Metrics
        metrics = self._calculate_metrics(y_val, y_pred, y_pred_proba)
        
        # Save ensemble model
        model_path = self.model_dir / "ensemble_model.pkl"
        with open(model_path, "wb") as f:
            pickle.dump(ensemble, f)
        
        self.models['ensemble'] = ensemble
        self.model_metrics['ensemble'] = metrics
        
        logger.info(f"Ensemble - Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1_score']:.4f}")
        
        return metrics
    
    def train_all_models(self, dataset_name: str = "phishing_dataset.csv") -> Dict[str, Dict]:
        """Train all models in the pipeline."""
        logger.info("Starting complete model training pipeline...")
        
        # Load and preprocess data
        data = self.data_loader.load_dataset(dataset_name)
        if data is None:
            raise ValueError("Failed to load dataset")
        
        X, y = self.data_loader.preprocess_features(data, fit_scalers=True)
        X_train, X_val, X_test, y_train, y_val, y_test = self.data_loader.split_dataset(X, y)
        
        # Save preprocessors
        self.data_loader.save_preprocessors(str(self.model_dir))
        
        # Train individual models
        all_metrics = {}
        
        try:
            all_metrics['random_forest'] = self.train_random_forest(X_train, y_train, X_val, y_val)
        except Exception as e:
            logger.error(f"Random Forest training failed: {e}")
        
        try:
            all_metrics['svm'] = self.train_svm(X_train, y_train, X_val, y_val)
        except Exception as e:
            logger.error(f"SVM training failed: {e}")
        
        try:
            all_metrics['deep_learning'] = self.train_deep_learning(X_train, y_train, X_val, y_val)
        except Exception as e:
            logger.error(f"Deep Learning training failed: {e}")
        
        # Create ensemble if we have multiple models
        if len(self.models) >= 2:
            try:
                all_metrics['ensemble'] = self.create_ensemble_model(X_train, y_train, X_val, y_val)
            except Exception as e:
                logger.error(f"Ensemble creation failed: {e}")
        
        # Final evaluation on test set
        test_metrics = self.evaluate_on_test_set(X_test, y_test)
        all_metrics['test_results'] = test_metrics
        
        # Save training results
        self._save_training_results(all_metrics)
        
        logger.info("Model training pipeline completed successfully")
        
        return all_metrics
    
    def evaluate_on_test_set(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Dict]:
        """Evaluate all trained models on test set."""
        test_results = {}
        
        for model_name, model in self.models.items():
            try:
                if model_name == 'deep_learning' and TENSORFLOW_AVAILABLE:
                    y_pred_proba = model.predict(X_test).flatten()
                    y_pred = (y_pred_proba > 0.5).astype(int)
                else:
                    y_pred = model.predict(X_test)
                    y_pred_proba = model.predict_proba(X_test)[:, 1]
                
                metrics = self._calculate_metrics(y_test, y_pred, y_pred_proba)
                test_results[model_name] = metrics
                
                logger.info(f"{model_name} Test - Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1_score']:.4f}")
                
            except Exception as e:
                logger.error(f"Test evaluation failed for {model_name}: {e}")
        
        return test_results
    
    def _calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, 
                         y_pred_proba: np.ndarray) -> Dict[str, Any]:
        """Calculate comprehensive evaluation metrics."""
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred),
            'recall': recall_score(y_true, y_pred),
            'f1_score': f1_score(y_true, y_pred),
            'roc_auc': roc_auc_score(y_true, y_pred_proba),
            'confusion_matrix': confusion_matrix(y_true, y_pred).tolist(),
            'classification_report': classification_report(y_true, y_pred, output_dict=True)
        }
        
        return metrics
    
    def _save_training_results(self, results: Dict[str, Dict]):
        """Save training results to file and database."""
        # Save to JSON file
        results_file = self.model_dir / "training_results.json"
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        
        # Save to database
        try:
            self._save_to_database(results)
        except Exception as e:
            logger.error(f"Failed to save results to database: {e}")
    
    async def _save_to_database(self, results: Dict[str, Dict]):
        """Save training results to database."""
        for model_name, metrics in results.items():
            if model_name == 'test_results':
                continue
            
            query = """
            INSERT INTO model_training_history 
            (model_name, model_version, accuracy, precision_score, recall, f1_score, 
             training_samples, validation_samples, model_file_path, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """
            
            model_version = datetime.now().strftime("%Y%m%d_%H%M%S")
            model_file_path = str(self.model_dir / f"{model_name}.pkl")
            
            await db_manager.execute_command(
                query,
                model_name,
                model_version,
                metrics.get('accuracy', 0),
                metrics.get('precision', 0),
                metrics.get('recall', 0),
                metrics.get('f1_score', 0),
                0,  # training_samples - would need to track this
                0,  # validation_samples - would need to track this
                model_file_path,
                True  # is_active
            )
