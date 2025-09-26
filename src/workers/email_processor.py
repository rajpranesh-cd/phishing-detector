"""
Background tasks for email processing and analysis.
"""
import asyncio
from celery import current_task
from typing import Dict, Any, List
import logging
from datetime import datetime, timedelta

from .celery_app import celery_app
from ..core.phishing_detector import PhishingDetector
from ..integrations.graph_api import GraphAPIClient
from ..utils.database import get_db_connection
from ..utils.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

@celery_app.task(bind=True, max_retries=3)
def process_email_batch(self, email_ids: List[str]) -> Dict[str, Any]:
    """
    Process a batch of emails for phishing detection.
    """
    try:
        logger.info(f"Processing batch of {len(email_ids)} emails")
        
        # Update task progress
        current_task.update_state(
            state="PROGRESS",
            meta={"current": 0, "total": len(email_ids), "status": "Starting batch processing"}
        )
        
        detector = PhishingDetector()
        asyncio.run(detector.initialize())
        
        graph_client = GraphAPIClient()
        results = []
        
        for i, email_id in enumerate(email_ids):
            try:
                # Fetch email from Graph API
                email_data = asyncio.run(graph_client.get_email(email_id))
                
                if email_data:
                    # Analyze email
                    analysis_result = asyncio.run(detector.analyze_email(
                        sender=email_data.get("sender", {}).get("emailAddress", {}).get("address"),
                        subject=email_data.get("subject", ""),
                        body=email_data.get("body", {}).get("content", ""),
                        headers=email_data.get("internetMessageHeaders", {}),
                        attachments=email_data.get("attachments", [])
                    ))
                    
                    # Store result
                    store_analysis_result(analysis_result, email_id)
                    
                    # Quarantine if high threat
                    if analysis_result.get("threat_level") == "HIGH":
                        asyncio.run(graph_client.move_to_quarantine(email_id))
                        logger.warning(f"Quarantined high-threat email: {email_id}")
                    
                    results.append({
                        "email_id": email_id,
                        "status": "processed",
                        "threat_level": analysis_result.get("threat_level"),
                        "threat_score": analysis_result.get("threat_score")
                    })
                else:
                    results.append({
                        "email_id": email_id,
                        "status": "not_found"
                    })
                
                # Update progress
                current_task.update_state(
                    state="PROGRESS",
                    meta={
                        "current": i + 1,
                        "total": len(email_ids),
                        "status": f"Processed {i + 1}/{len(email_ids)} emails"
                    }
                )
                
            except Exception as e:
                logger.error(f"Failed to process email {email_id}: {str(e)}")
                results.append({
                    "email_id": email_id,
                    "status": "error",
                    "error": str(e)
                })
        
        logger.info(f"Completed batch processing: {len(results)} emails processed")
        return {
            "status": "completed",
            "processed": len(results),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Batch processing failed: {str(e)}")
        self.retry(countdown=60, exc=e)

@celery_app.task(bind=True)
def process_single_email(self, email_id: str, priority: str = "normal") -> Dict[str, Any]:
    """
    Process a single email for phishing detection.
    """
    try:
        logger.info(f"Processing single email: {email_id}")
        
        detector = PhishingDetector()
        asyncio.run(detector.initialize())
        
        graph_client = GraphAPIClient()
        
        # Fetch email
        email_data = asyncio.run(graph_client.get_email(email_id))
        
        if not email_data:
            return {"status": "not_found", "email_id": email_id}
        
        # Analyze email
        analysis_result = asyncio.run(detector.analyze_email(
            sender=email_data.get("sender", {}).get("emailAddress", {}).get("address"),
            subject=email_data.get("subject", ""),
            body=email_data.get("body", {}).get("content", ""),
            headers=email_data.get("internetMessageHeaders", {}),
            attachments=email_data.get("attachments", [])
        ))
        
        # Store result
        store_analysis_result(analysis_result, email_id)
        
        # Handle high-priority threats immediately
        if analysis_result.get("threat_level") == "HIGH":
            asyncio.run(graph_client.move_to_quarantine(email_id))
            
            # Send alert for high-priority emails
            if priority == "high":
                send_threat_alert.delay(email_id, analysis_result)
        
        return {
            "status": "processed",
            "email_id": email_id,
            "threat_level": analysis_result.get("threat_level"),
            "threat_score": analysis_result.get("threat_score"),
            "is_quarantined": analysis_result.get("threat_level") == "HIGH"
        }
        
    except Exception as e:
        logger.error(f"Failed to process email {email_id}: {str(e)}")
        self.retry(countdown=30, exc=e)

@celery_app.task
def send_threat_alert(email_id: str, analysis_result: Dict[str, Any]):
    """
    Send alert for high-threat emails.
    """
    try:
        # TODO: Implement email/Slack/Teams notifications
        logger.warning(f"HIGH THREAT ALERT - Email: {email_id}, Score: {analysis_result.get('threat_score')}")
        
        # Store alert in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO threat_alerts (email_id, threat_level, threat_score, alert_sent_at)
            VALUES (%s, %s, %s, NOW())
        """, (email_id, analysis_result.get("threat_level"), analysis_result.get("threat_score")))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Failed to send threat alert: {str(e)}")

@celery_app.task
def cleanup_old_data():
    """
    Clean up old analysis data and logs.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete analysis data older than 90 days
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        
        cursor.execute("""
            DELETE FROM email_analysis 
            WHERE created_at < %s AND is_quarantined = false
        """, (cutoff_date,))
        
        deleted_count = cursor.rowcount
        
        # Clean up old performance metrics
        cursor.execute("""
            DELETE FROM performance_metrics 
            WHERE created_at < %s
        """, (cutoff_date,))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Cleaned up {deleted_count} old analysis records")
        
    except Exception as e:
        logger.error(f"Data cleanup failed: {str(e)}")

def store_analysis_result(result: Dict[str, Any], email_id: str):
    """
    Store analysis result in database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO email_analysis (
            email_id, sender_email, recipient_email, subject,
            threat_level, threat_score, is_phishing, confidence,
            analysis_details, is_quarantined, created_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (email_id) DO UPDATE SET
            threat_level = EXCLUDED.threat_level,
            threat_score = EXCLUDED.threat_score,
            is_phishing = EXCLUDED.is_phishing,
            confidence = EXCLUDED.confidence,
            analysis_details = EXCLUDED.analysis_details,
            is_quarantined = EXCLUDED.is_quarantined,
            updated_at = NOW()
    """, (
        email_id,
        result.get("sender_email"),
        result.get("recipient_email"),
        result.get("subject"),
        result.get("threat_level"),
        result.get("threat_score"),
        result.get("is_phishing"),
        result.get("confidence"),
        result.get("analysis_details"),
        result.get("threat_level") == "HIGH"
    ))
    
    conn.commit()
    conn.close()
