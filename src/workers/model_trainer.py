"""
Background tasks for machine learning model training and updates.
"""
import asyncio
from celery import current_task
from typing import Dict, Any
import logging
from datetime import datetime, timedelta

from .celery_app import celery_app
from ..ml.model_trainer import ModelTrainer
from ..ml.data_loader import DataLoader
from ..utils.database import get_db_connection

logger = logging.getLogger(__name__)

@celery_app.task(bind=True)
def retrain_models(self):
    """
    Retrain ML models with latest data.
    """
    try:
        logger.info("Starting model retraining")
        
        current_task.update_state(
            state="PROGRESS",
            meta={"status": "Loading training data"}
        )
        
        # Load fresh training data
        data_loader = DataLoader()
        training_data = data_loader.load_training_data()
        
        if len(training_data) < 1000:
            logger.warning("Insufficient training data, skipping retraining")
            return {"status": "skipped", "reason": "insufficient_data"}
        
        current_task.update_state(
            state="PROGRESS",
            meta={"status": "Training models"}
        )
        
        # Train models
        trainer = ModelTrainer()
        results = asyncio.run(trainer.train_ensemble(training_data))
        
        current_task.update_state(
            state="PROGRESS",
            meta={"status": "Evaluating models"}
        )
        
        # Evaluate and save best models
        best_models = trainer.evaluate_and_select_best(results)
        trainer.save_models(best_models)
        
        # Update model metadata in database
        update_model_metadata(best_models)
        
        logger.info("Model retraining completed successfully")
        return {
            "status": "completed",
            "models_trained": len(best_models),
            "performance": {model: metrics for model, metrics in best_models.items()}
        }
        
    except Exception as e:
        logger.error(f"Model retraining failed: {str(e)}")
        self.retry(countdown=3600, exc=e)  # Retry in 1 hour

@celery_app.task
def update_feature_importance():
    """
    Update feature importance analysis.
    """
    try:
        trainer = ModelTrainer()
        importance_data = trainer.analyze_feature_importance()
        
        # Store in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO feature_importance (analysis_date, importance_data)
            VALUES (NOW(), %s)
        """, (importance_data,))
        
        conn.commit()
        conn.close()
        
        logger.info("Feature importance analysis updated")
        
    except Exception as e:
        logger.error(f"Feature importance update failed: {str(e)}")

def update_model_metadata(models: Dict[str, Any]):
    """
    Update model metadata in database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    for model_name, metrics in models.items():
        cursor.execute("""
            INSERT INTO model_metadata (
                model_name, version, accuracy, precision, recall, f1_score,
                training_date, is_active
            ) VALUES (%s, %s, %s, %s, %s, %s, NOW(), true)
        """, (
            model_name,
            datetime.utcnow().strftime("%Y%m%d_%H%M%S"),
            metrics.get("accuracy"),
            metrics.get("precision"),
            metrics.get("recall"),
            metrics.get("f1_score")
        ))
        
        # Deactivate old versions
        cursor.execute("""
            UPDATE model_metadata 
            SET is_active = false 
            WHERE model_name = %s AND training_date < NOW() - INTERVAL '1 day'
        """, (model_name,))
    
    conn.commit()
    conn.close()
