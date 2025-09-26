"""
Celery application configuration for background task processing.
"""
from celery import Celery
from ..utils.config import get_settings

settings = get_settings()

# Create Celery app
celery_app = Celery(
    "phishing_detector",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "src.workers.email_processor",
        "src.workers.model_trainer",
        "src.workers.report_generator"
    ]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)

# Task routing
celery_app.conf.task_routes = {
    "src.workers.email_processor.*": {"queue": "email_processing"},
    "src.workers.model_trainer.*": {"queue": "ml_training"},
    "src.workers.report_generator.*": {"queue": "reporting"},
}

# Periodic tasks
celery_app.conf.beat_schedule = {
    "retrain-models": {
        "task": "src.workers.model_trainer.retrain_models",
        "schedule": 24 * 60 * 60,  # Daily
    },
    "generate-daily-report": {
        "task": "src.workers.report_generator.generate_daily_report",
        "schedule": 24 * 60 * 60,  # Daily at midnight
    },
    "cleanup-old-data": {
        "task": "src.workers.email_processor.cleanup_old_data",
        "schedule": 7 * 24 * 60 * 60,  # Weekly
    },
}
