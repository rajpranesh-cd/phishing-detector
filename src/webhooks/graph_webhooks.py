"""
Microsoft Graph webhook handlers for real-time email notifications.
"""
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from typing import Dict, Any
import hmac
import hashlib
import json
import logging

from ..workers.email_processor import process_single_email
from ..utils.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

@router.post("/graph/notifications")
async def handle_graph_notification(
    request: Request,
    background_tasks: BackgroundTasks
):
    """
    Handle Microsoft Graph webhook notifications for new emails.
    """
    try:
        # Verify webhook signature
        body = await request.body()
        signature = request.headers.get("x-ms-signature")
        
        if not verify_webhook_signature(body, signature):
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        # Parse notification
        notification_data = json.loads(body)
        
        for notification in notification_data.get("value", []):
            change_type = notification.get("changeType")
            resource = notification.get("resource")
            
            if change_type == "created" and "messages" in resource:
                # New email received
                email_id = extract_email_id(resource)
                
                if email_id:
                    # Process email in background with high priority
                    process_single_email.delay(email_id, priority="high")
                    logger.info(f"Queued real-time processing for email: {email_id}")
        
        return {"status": "processed"}
        
    except Exception as e:
        logger.error(f"Webhook processing failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")

@router.get("/graph/validation")
async def validate_webhook(validationToken: str):
    """
    Validate Microsoft Graph webhook subscription.
    """
    return {"validationToken": validationToken}

def verify_webhook_signature(body: bytes, signature: str) -> bool:
    """
    Verify webhook signature using client secret.
    """
    if not signature:
        return False
    
    try:
        expected_signature = hmac.new(
            settings.GRAPH_CLIENT_SECRET.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
        
    except Exception as e:
        logger.error(f"Signature verification failed: {str(e)}")
        return False

def extract_email_id(resource: str) -> str:
    """
    Extract email ID from Graph API resource string.
    """
    try:
        # Resource format: /users/{user-id}/messages/{message-id}
        parts = resource.split("/")
        if len(parts) >= 4 and parts[3] == "messages":
            return parts[4]
    except Exception as e:
        logger.error(f"Failed to extract email ID: {str(e)}")
    
    return None
