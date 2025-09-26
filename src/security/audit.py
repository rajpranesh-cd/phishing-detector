"""
Audit logging and security monitoring.
"""
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum
import json

from ..utils.database import get_db_connection

logger = logging.getLogger(__name__)

class AuditEventType(str, Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    EMAIL_ANALYSIS = "email_analysis"
    QUARANTINE_ACTION = "quarantine_action"
    ADMIN_ACTION = "admin_action"
    API_ACCESS = "api_access"
    SECURITY_ALERT = "security_alert"
    DATA_EXPORT = "data_export"
    CONFIG_CHANGE = "config_change"

class AuditLogger:
    """
    Centralized audit logging system.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("audit")
    
    def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True
    ):
        """
        Log audit event to database and file.
        """
        try:
            # Create audit record
            audit_record = {
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": event_type.value,
                "user_id": user_id,
                "user_email": user_email,
                "resource_id": resource_id,
                "action": action,
                "details": details or {},
                "ip_address": ip_address,
                "user_agent": user_agent,
                "success": success
            }
            
            # Log to file
            self.logger.info(json.dumps(audit_record))
            
            # Store in database
            self._store_audit_record(audit_record)
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {str(e)}")
    
    def _store_audit_record(self, record: Dict[str, Any]):
        """
        Store audit record in database.
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO audit_logs (
                    event_type, user_id, user_email, resource_id, action,
                    details, ip_address, user_agent, success, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                record["event_type"],
                record["user_id"],
                record["user_email"],
                record["resource_id"],
                record["action"],
                json.dumps(record["details"]),
                record["ip_address"],
                record["user_agent"],
                record["success"],
                datetime.utcnow()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store audit record: {str(e)}")
    
    def get_audit_trail(
        self,
        user_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> list:
        """
        Retrieve audit trail with filters.
        """
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            query = "SELECT * FROM audit_logs WHERE 1=1"
            params = []
            
            if user_id:
                query += " AND user_id = %s"
                params.append(user_id)
            
            if event_type:
                query += " AND event_type = %s"
                params.append(event_type.value)
            
            if start_date:
                query += " AND created_at >= %s"
                params.append(start_date)
            
            if end_date:
                query += " AND created_at <= %s"
                params.append(end_date)
            
            query += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            records = cursor.fetchall()
            conn.close()
            
            return records
            
        except Exception as e:
            logger.error(f"Failed to retrieve audit trail: {str(e)}")
            return []

# Global audit logger instance
audit_logger = AuditLogger()
