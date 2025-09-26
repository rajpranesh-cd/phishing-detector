"""
Pydantic models for API requests and responses.
"""
from pydantic import BaseModel, EmailStr
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum

class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class EmailAnalysisRequest(BaseModel):
    sender_email: EmailStr
    recipient_email: Optional[EmailStr] = None
    subject: str
    body: str
    headers: Dict[str, str] = {}
    attachments: List[Dict[str, Any]] = []

class EmailAnalysisResult(BaseModel):
    email_id: Optional[str] = None
    sender_email: str
    subject: str
    threat_level: ThreatLevel
    threat_score: float
    is_phishing: bool
    confidence: float
    analysis_details: Dict[str, Any] = {}
    analyzed_at: datetime

class QuarantinedEmail(BaseModel):
    email_id: str
    sender_email: str
    subject: str
    threat_level: ThreatLevel
    threat_score: float
    quarantined_at: datetime
    quarantine_reason: str

class SystemStats(BaseModel):
    total_emails_analyzed: int
    high_threat_emails: int
    medium_threat_emails: int
    low_threat_emails: int
    quarantined_emails: int
    recent_activity: List[EmailAnalysisResult]

class UserProfile(BaseModel):
    user_id: str
    email: str
    name: str
    department: Optional[str] = None
    risk_level: ThreatLevel
    last_login: Optional[datetime] = None

class WebhookPayload(BaseModel):
    subscription_id: str
    change_type: str
    resource: str
    resource_data: Dict[str, Any]
    client_state: Optional[str] = None
