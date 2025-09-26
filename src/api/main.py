"""
Main FastAPI application for the phishing detection system.
"""
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import uvicorn
from typing import List, Optional
import asyncio
from datetime import datetime, timedelta

from ..utils.config import get_settings
from ..utils.database import get_db_connection
from ..core.phishing_detector import PhishingDetector
from ..integrations.graph_api import GraphAPIClient
from .models import *
from .dependencies import get_current_user, get_phishing_detector

settings = get_settings()

app = FastAPI(
    title="AI Phishing Detection System",
    description="Enterprise-grade email security with AI-powered threat detection",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize components
phishing_detector = None

@app.on_event("startup")
async def startup_event():
    """Initialize application components on startup."""
    global phishing_detector
    phishing_detector = PhishingDetector()
    await phishing_detector.initialize()

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the main dashboard."""
    with open("static/dashboard.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

@app.get("/api/stats", response_model=SystemStats)
async def get_system_stats():
    """Get system statistics."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get email analysis stats
    cursor.execute("""
        SELECT 
            COUNT(*) as total_emails,
            COUNT(CASE WHEN threat_level = 'HIGH' THEN 1 END) as high_threats,
            COUNT(CASE WHEN threat_level = 'MEDIUM' THEN 1 END) as medium_threats,
            COUNT(CASE WHEN threat_level = 'LOW' THEN 1 END) as low_threats,
            COUNT(CASE WHEN is_quarantined = true THEN 1 END) as quarantined
        FROM email_analysis 
        WHERE created_at >= NOW() - INTERVAL '24 hours'
    """)
    
    stats = cursor.fetchone()
    
    # Get recent activity
    cursor.execute("""
        SELECT sender_email, subject, threat_level, threat_score, created_at
        FROM email_analysis 
        ORDER BY created_at DESC 
        LIMIT 10
    """)
    
    recent_activity = cursor.fetchall()
    
    conn.close()
    
    return SystemStats(
        total_emails_analyzed=stats[0] or 0,
        high_threat_emails=stats[1] or 0,
        medium_threat_emails=stats[2] or 0,
        low_threat_emails=stats[3] or 0,
        quarantined_emails=stats[4] or 0,
        recent_activity=[
            EmailAnalysisResult(
                sender_email=row[0],
                subject=row[1],
                threat_level=row[2],
                threat_score=row[3],
                analyzed_at=row[4]
            ) for row in recent_activity
        ]
    )

@app.post("/api/analyze-email", response_model=EmailAnalysisResult)
async def analyze_email(
    request: EmailAnalysisRequest,
    background_tasks: BackgroundTasks,
    detector: PhishingDetector = Depends(get_phishing_detector)
):
    """Analyze a single email for phishing threats."""
    try:
        result = await detector.analyze_email(
            sender=request.sender_email,
            subject=request.subject,
            body=request.body,
            headers=request.headers,
            attachments=request.attachments
        )
        
        # Store result in background
        background_tasks.add_task(store_analysis_result, result)
        
        return EmailAnalysisResult(
            email_id=result.get('email_id'),
            sender_email=request.sender_email,
            subject=request.subject,
            threat_level=result.get('threat_level'),
            threat_score=result.get('threat_score'),
            is_phishing=result.get('is_phishing', False),
            confidence=result.get('confidence', 0.0),
            analysis_details=result.get('analysis_details', {}),
            analyzed_at=datetime.utcnow()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/quarantine", response_model=List[QuarantinedEmail])
async def get_quarantined_emails(
    page: int = 1,
    limit: int = 50,
    user=Depends(get_current_user)
):
    """Get quarantined emails with pagination."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    offset = (page - 1) * limit
    
    cursor.execute("""
        SELECT email_id, sender_email, subject, threat_level, 
               threat_score, quarantined_at, quarantine_reason
        FROM email_analysis 
        WHERE is_quarantined = true 
        ORDER BY quarantined_at DESC 
        LIMIT %s OFFSET %s
    """, (limit, offset))
    
    emails = cursor.fetchall()
    conn.close()
    
    return [
        QuarantinedEmail(
            email_id=row[0],
            sender_email=row[1],
            subject=row[2],
            threat_level=row[3],
            threat_score=row[4],
            quarantined_at=row[5],
            quarantine_reason=row[6]
        ) for row in emails
    ]

@app.post("/api/quarantine/{email_id}/release")
async def release_from_quarantine(
    email_id: str,
    user=Depends(get_current_user)
):
    """Release an email from quarantine."""
    try:
        # Update database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE email_analysis 
            SET is_quarantined = false, released_at = NOW(), released_by = %s
            WHERE email_id = %s
        """, (user.get('email'), email_id))
        
        conn.commit()
        conn.close()
        
        # TODO: Move email back to inbox via Graph API
        
        return {"message": "Email released from quarantine successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Release failed: {str(e)}")

@app.get("/api/reports/threat-trends")
async def get_threat_trends(
    days: int = 30,
    user=Depends(get_current_user)
):
    """Get threat trends over time."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            DATE(created_at) as date,
            threat_level,
            COUNT(*) as count
        FROM email_analysis 
        WHERE created_at >= NOW() - INTERVAL '%s days'
        GROUP BY DATE(created_at), threat_level
        ORDER BY date DESC
    """, (days,))
    
    results = cursor.fetchall()
    conn.close()
    
    # Group by date
    trends = {}
    for row in results:
        date_str = row[0].isoformat()
        if date_str not in trends:
            trends[date_str] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        trends[date_str][row[1]] = row[2]
    
    return {"trends": trends}

@app.get("/api/users/{user_id}/risk-profile")
async def get_user_risk_profile(
    user_id: str,
    admin_user=Depends(get_current_user)
):
    """Get risk profile for a specific user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            COUNT(*) as total_emails,
            COUNT(CASE WHEN threat_level = 'HIGH' THEN 1 END) as high_threats,
            AVG(threat_score) as avg_threat_score,
            MAX(created_at) as last_threat
        FROM email_analysis 
        WHERE recipient_email = %s
        AND created_at >= NOW() - INTERVAL '30 days'
    """, (user_id,))
    
    profile = cursor.fetchone()
    conn.close()
    
    return {
        "user_id": user_id,
        "total_emails": profile[0] or 0,
        "high_threat_emails": profile[1] or 0,
        "average_threat_score": float(profile[2] or 0),
        "last_threat_date": profile[3].isoformat() if profile[3] else None,
        "risk_level": "HIGH" if (profile[1] or 0) > 5 else "MEDIUM" if (profile[1] or 0) > 1 else "LOW"
    }

async def store_analysis_result(result: dict):
    """Store analysis result in database (background task)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO email_analysis (
            email_id, sender_email, recipient_email, subject,
            threat_level, threat_score, is_phishing, confidence,
            analysis_details, is_quarantined
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        result.get('email_id'),
        result.get('sender_email'),
        result.get('recipient_email'),
        result.get('subject'),
        result.get('threat_level'),
        result.get('threat_score'),
        result.get('is_phishing'),
        result.get('confidence'),
        result.get('analysis_details'),
        result.get('is_quarantined', False)
    ))
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
