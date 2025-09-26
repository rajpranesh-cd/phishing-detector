"""
Background tasks for generating reports and analytics.
"""
from celery import current_task
from typing import Dict, Any, List
import logging
from datetime import datetime, timedelta
import json

from .celery_app import celery_app
from ..utils.database import get_db_connection

logger = logging.getLogger(__name__)

@celery_app.task(bind=True)
def generate_daily_report(self):
    """
    Generate daily security report.
    """
    try:
        logger.info("Generating daily security report")
        
        current_task.update_state(
            state="PROGRESS",
            meta={"status": "Collecting data"}
        )
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get yesterday's data
        yesterday = datetime.utcnow() - timedelta(days=1)
        
        # Email analysis summary
        cursor.execute("""
            SELECT 
                COUNT(*) as total_emails,
                COUNT(CASE WHEN threat_level = 'HIGH' THEN 1 END) as high_threats,
                COUNT(CASE WHEN threat_level = 'MEDIUM' THEN 1 END) as medium_threats,
                COUNT(CASE WHEN threat_level = 'LOW' THEN 1 END) as low_threats,
                COUNT(CASE WHEN is_quarantined = true THEN 1 END) as quarantined,
                AVG(threat_score) as avg_threat_score
            FROM email_analysis 
            WHERE DATE(created_at) = DATE(%s)
        """, (yesterday,))
        
        daily_stats = cursor.fetchone()
        
        # Top threat senders
        cursor.execute("""
            SELECT sender_email, COUNT(*) as threat_count, AVG(threat_score) as avg_score
            FROM email_analysis 
            WHERE DATE(created_at) = DATE(%s) AND threat_level IN ('HIGH', 'MEDIUM')
            GROUP BY sender_email
            ORDER BY threat_count DESC, avg_score DESC
            LIMIT 10
        """, (yesterday,))
        
        top_threats = cursor.fetchall()
        
        # Model performance
        cursor.execute("""
            SELECT model_name, accuracy, precision, recall, f1_score
            FROM model_metadata 
            WHERE is_active = true
        """)
        
        model_performance = cursor.fetchall()
        
        current_task.update_state(
            state="PROGRESS",
            meta={"status": "Generating report"}
        )
        
        # Generate report
        report = {
            "date": yesterday.strftime("%Y-%m-%d"),
            "summary": {
                "total_emails": daily_stats[0] or 0,
                "high_threats": daily_stats[1] or 0,
                "medium_threats": daily_stats[2] or 0,
                "low_threats": daily_stats[3] or 0,
                "quarantined": daily_stats[4] or 0,
                "average_threat_score": float(daily_stats[5] or 0)
            },
            "top_threat_senders": [
                {
                    "sender": row[0],
                    "threat_count": row[1],
                    "average_score": float(row[2])
                } for row in top_threats
            ],
            "model_performance": [
                {
                    "model": row[0],
                    "accuracy": float(row[1]),
                    "precision": float(row[2]),
                    "recall": float(row[3]),
                    "f1_score": float(row[4])
                } for row in model_performance
            ]
        }
        
        # Store report
        cursor.execute("""
            INSERT INTO daily_reports (report_date, report_data)
            VALUES (%s, %s)
        """, (yesterday.date(), json.dumps(report)))
        
        conn.commit()
        conn.close()
        
        logger.info("Daily report generated successfully")
        return {"status": "completed", "report": report}
        
    except Exception as e:
        logger.error(f"Daily report generation failed: {str(e)}")
        self.retry(countdown=1800, exc=e)  # Retry in 30 minutes

@celery_app.task
def generate_weekly_summary():
    """
    Generate weekly security summary.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get last 7 days of data
        week_ago = datetime.utcnow() - timedelta(days=7)
        
        cursor.execute("""
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as total_emails,
                COUNT(CASE WHEN threat_level = 'HIGH' THEN 1 END) as high_threats,
                AVG(threat_score) as avg_score
            FROM email_analysis 
            WHERE created_at >= %s
            GROUP BY DATE(created_at)
            ORDER BY date
        """, (week_ago,))
        
        weekly_data = cursor.fetchall()
        
        # Calculate trends
        total_emails = sum(row[1] for row in weekly_data)
        total_threats = sum(row[2] for row in weekly_data)
        threat_rate = (total_threats / total_emails * 100) if total_emails > 0 else 0
        
        summary = {
            "week_ending": datetime.utcnow().strftime("%Y-%m-%d"),
            "total_emails": total_emails,
            "total_high_threats": total_threats,
            "threat_rate_percent": round(threat_rate, 2),
            "daily_breakdown": [
                {
                    "date": row[0].strftime("%Y-%m-%d"),
                    "emails": row[1],
                    "threats": row[2],
                    "avg_score": float(row[3] or 0)
                } for row in weekly_data
            ]
        }
        
        # Store summary
        cursor.execute("""
            INSERT INTO weekly_summaries (week_ending, summary_data)
            VALUES (%s, %s)
        """, (datetime.utcnow().date(), json.dumps(summary)))
        
        conn.commit()
        conn.close()
        
        logger.info("Weekly summary generated")
        return summary
        
    except Exception as e:
        logger.error(f"Weekly summary generation failed: {str(e)}")
