"""
System health monitoring and alerting.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

from ..utils.database import get_db_connection
from ..utils.config import get_settings
from ..workers.celery_app import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()

class HealthMonitor:
    """
    Monitor system health and performance metrics.
    """
    
    def __init__(self):
        self.metrics = {}
    
    async def check_system_health(self) -> Dict[str, Any]:
        """
        Perform comprehensive system health check.
        """
        health_status = {
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": "healthy",
            "components": {}
        }
        
        # Check database connectivity
        db_status = await self.check_database_health()
        health_status["components"]["database"] = db_status
        
        # Check Celery workers
        worker_status = await self.check_worker_health()
        health_status["components"]["workers"] = worker_status
        
        # Check ML models
        model_status = await self.check_model_health()
        health_status["components"]["models"] = model_status
        
        # Check processing performance
        performance_status = await self.check_performance_metrics()
        health_status["components"]["performance"] = performance_status
        
        # Determine overall status
        component_statuses = [comp["status"] for comp in health_status["components"].values()]
        if "critical" in component_statuses:
            health_status["overall_status"] = "critical"
        elif "warning" in component_statuses:
            health_status["overall_status"] = "warning"
        
        return health_status
    
    async def check_database_health(self) -> Dict[str, Any]:
        """
        Check database connectivity and performance.
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Test query
            start_time = datetime.utcnow()
            cursor.execute("SELECT 1")
            response_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Check recent activity
            cursor.execute("""
                SELECT COUNT(*) FROM email_analysis 
                WHERE created_at >= NOW() - INTERVAL '1 hour'
            """)
            recent_analyses = cursor.fetchone()[0]
            
            conn.close()
            
            status = "healthy"
            if response_time > 1.0:
                status = "warning"
            if response_time > 5.0:
                status = "critical"
            
            return {
                "status": status,
                "response_time_seconds": response_time,
                "recent_analyses": recent_analyses,
                "message": f"Database responding in {response_time:.3f}s"
            }
            
        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}")
            return {
                "status": "critical",
                "error": str(e),
                "message": "Database connection failed"
            }
    
    async def check_worker_health(self) -> Dict[str, Any]:
        """
        Check Celery worker status and queue lengths.
        """
        try:
            # Get active workers
            inspect = celery_app.control.inspect()
            active_workers = inspect.active()
            
            if not active_workers:
                return {
                    "status": "critical",
                    "message": "No active workers found",
                    "active_workers": 0
                }
            
            # Check queue lengths
            queue_lengths = {}
            for queue in ["email_processing", "ml_training", "reporting"]:
                try:
                    length = celery_app.control.inspect().active_queues()
                    queue_lengths[queue] = len(length.get(queue, []))
                except:
                    queue_lengths[queue] = 0
            
            total_queue_length = sum(queue_lengths.values())
            
            status = "healthy"
            if total_queue_length > 100:
                status = "warning"
            if total_queue_length > 500:
                status = "critical"
            
            return {
                "status": status,
                "active_workers": len(active_workers),
                "queue_lengths": queue_lengths,
                "total_queued": total_queue_length,
                "message": f"{len(active_workers)} workers active, {total_queue_length} tasks queued"
            }
            
        except Exception as e:
            logger.error(f"Worker health check failed: {str(e)}")
            return {
                "status": "warning",
                "error": str(e),
                "message": "Worker status check failed"
            }
    
    async def check_model_health(self) -> Dict[str, Any]:
        """
        Check ML model availability and performance.
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check active models
            cursor.execute("""
                SELECT model_name, accuracy, training_date
                FROM model_metadata 
                WHERE is_active = true
            """)
            
            active_models = cursor.fetchall()
            conn.close()
            
            if not active_models:
                return {
                    "status": "critical",
                    "message": "No active models found",
                    "active_models": 0
                }
            
            # Check model age
            oldest_model = min(row[2] for row in active_models)
            model_age_days = (datetime.utcnow() - oldest_model).days
            
            status = "healthy"
            if model_age_days > 7:
                status = "warning"
            if model_age_days > 30:
                status = "critical"
            
            avg_accuracy = sum(row[1] for row in active_models) / len(active_models)
            
            return {
                "status": status,
                "active_models": len(active_models),
                "average_accuracy": round(avg_accuracy, 3),
                "oldest_model_days": model_age_days,
                "message": f"{len(active_models)} models active, avg accuracy: {avg_accuracy:.1%}"
            }
            
        except Exception as e:
            logger.error(f"Model health check failed: {str(e)}")
            return {
                "status": "warning",
                "error": str(e),
                "message": "Model status check failed"
            }
    
    async def check_performance_metrics(self) -> Dict[str, Any]:
        """
        Check system performance metrics.
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check processing times
            cursor.execute("""
                SELECT AVG(processing_time_ms), COUNT(*)
                FROM performance_metrics 
                WHERE created_at >= NOW() - INTERVAL '1 hour'
            """)
            
            perf_data = cursor.fetchone()
            avg_processing_time = perf_data[0] or 0
            recent_processed = perf_data[1] or 0
            
            # Check error rates
            cursor.execute("""
                SELECT 
                    COUNT(CASE WHEN status = 'error' THEN 1 END) as errors,
                    COUNT(*) as total
                FROM task_logs 
                WHERE created_at >= NOW() - INTERVAL '1 hour'
            """)
            
            error_data = cursor.fetchone()
            error_rate = (error_data[0] / error_data[1] * 100) if error_data[1] > 0 else 0
            
            conn.close()
            
            status = "healthy"
            if avg_processing_time > 5000 or error_rate > 5:
                status = "warning"
            if avg_processing_time > 10000 or error_rate > 15:
                status = "critical"
            
            return {
                "status": status,
                "avg_processing_time_ms": round(avg_processing_time, 2),
                "emails_processed_hour": recent_processed,
                "error_rate_percent": round(error_rate, 2),
                "message": f"Avg processing: {avg_processing_time:.0f}ms, Error rate: {error_rate:.1f}%"
            }
            
        except Exception as e:
            logger.error(f"Performance check failed: {str(e)}")
            return {
                "status": "warning",
                "error": str(e),
                "message": "Performance metrics unavailable"
            }
