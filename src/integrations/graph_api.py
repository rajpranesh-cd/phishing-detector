"""Microsoft Graph API client for email access and management."""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import aiohttp
from msal import ConfidentialClientApplication

from ..utils.config import settings

logger = logging.getLogger(__name__)


class GraphAPIClient:
    """Microsoft Graph API client for email operations."""
    
    def __init__(self):
        self.client_app = ConfidentialClientApplication(
            client_id=settings.azure_client_id,
            client_credential=settings.azure_client_secret,
            authority=f"https://login.microsoftonline.com/{settings.azure_tenant_id}"
        )
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        await self.authenticate()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def authenticate(self) -> bool:
        """Authenticate with Microsoft Graph API."""
        try:
            # Check if current token is still valid
            if self.access_token and self.token_expires_at:
                if datetime.now() < self.token_expires_at - timedelta(minutes=5):
                    return True
            
            # Get new token
            result = self.client_app.acquire_token_for_client(
                scopes=["https://graph.microsoft.com/.default"]
            )
            
            if "access_token" in result:
                self.access_token = result["access_token"]
                expires_in = result.get("expires_in", 3600)
                self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
                logger.info("Successfully authenticated with Microsoft Graph API")
                return True
            else:
                logger.error(f"Authentication failed: {result.get('error_description')}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    async def _make_request(self, method: str, url: str, **kwargs) -> Optional[Dict]:
        """Make authenticated request to Graph API."""
        if not await self.authenticate():
            raise Exception("Failed to authenticate with Graph API")
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        if "headers" in kwargs:
            headers.update(kwargs["headers"])
        kwargs["headers"] = headers
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 401:
                    # Token expired, retry once
                    self.access_token = None
                    if await self.authenticate():
                        headers["Authorization"] = f"Bearer {self.access_token}"
                        kwargs["headers"] = headers
                        async with self.session.request(method, url, **kwargs) as retry_response:
                            if retry_response.status == 200:
                                return await retry_response.json()
                
                error_text = await response.text()
                logger.error(f"Graph API request failed: {response.status} - {error_text}")
                return None
                
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None
    
    async def get_user_emails(self, user_email: str, folder: str = "inbox", 
                            limit: int = 50, filter_query: str = None) -> List[Dict]:
        """Get emails from user's mailbox."""
        url = f"https://graph.microsoft.com/v1.0/users/{user_email}/mailFolders/{folder}/messages"
        
        params = {
            "$top": limit,
            "$select": "id,subject,sender,toRecipients,receivedDateTime,body,hasAttachments,internetMessageHeaders",
            "$orderby": "receivedDateTime desc"
        }
        
        if filter_query:
            params["$filter"] = filter_query
        
        result = await self._make_request("GET", url, params=params)
        return result.get("value", []) if result else []
    
    async def get_email_details(self, user_email: str, message_id: str) -> Optional[Dict]:
        """Get detailed email information including headers and attachments."""
        url = f"https://graph.microsoft.com/v1.0/users/{user_email}/messages/{message_id}"
        
        params = {
            "$select": "id,subject,sender,toRecipients,ccRecipients,bccRecipients,receivedDateTime,sentDateTime,body,hasAttachments,internetMessageHeaders,internetMessageId"
        }
        
        return await self._make_request("GET", url, params=params)
    
    async def get_email_attachments(self, user_email: str, message_id: str) -> List[Dict]:
        """Get email attachments."""
        url = f"https://graph.microsoft.com/v1.0/users/{user_email}/messages/{message_id}/attachments"
        
        result = await self._make_request("GET", url)
        return result.get("value", []) if result else []
    
    async def move_email_to_folder(self, user_email: str, message_id: str, 
                                 destination_folder: str) -> bool:
        """Move email to specified folder."""
        url = f"https://graph.microsoft.com/v1.0/users/{user_email}/messages/{message_id}/move"
        
        data = {
            "destinationId": destination_folder
        }
        
        result = await self._make_request("POST", url, json=data)
        return result is not None
    
    async def create_folder(self, user_email: str, folder_name: str, 
                          parent_folder: str = "inbox") -> Optional[str]:
        """Create a new mail folder."""
        url = f"https://graph.microsoft.com/v1.0/users/{user_email}/mailFolders/{parent_folder}/childFolders"
        
        data = {
            "displayName": folder_name
        }
        
        result = await self._make_request("POST", url, json=data)
        return result.get("id") if result else None
    
    async def get_or_create_quarantine_folder(self, user_email: str) -> Optional[str]:
        """Get or create quarantine folder for suspicious emails."""
        # First, try to find existing quarantine folder
        url = f"https://graph.microsoft.com/v1.0/users/{user_email}/mailFolders"
        result = await self._make_request("GET", url)
        
        if result:
            for folder in result.get("value", []):
                if folder.get("displayName") == "Phishing Quarantine":
                    return folder.get("id")
        
        # Create quarantine folder if it doesn't exist
        return await self.create_folder(user_email, "Phishing Quarantine")
    
    async def create_webhook_subscription(self, user_email: str, 
                                        notification_url: str) -> Optional[Dict]:
        """Create webhook subscription for email notifications."""
        url = "https://graph.microsoft.com/v1.0/subscriptions"
        
        data = {
            "changeType": "created,updated",
            "notificationUrl": notification_url,
            "resource": f"users/{user_email}/mailFolders/inbox/messages",
            "expirationDateTime": (datetime.now() + timedelta(days=3)).isoformat() + "Z",
            "clientState": settings.webhook_secret
        }
        
        return await self._make_request("POST", url, json=data)
    
    async def renew_subscription(self, subscription_id: str) -> bool:
        """Renew webhook subscription."""
        url = f"https://graph.microsoft.com/v1.0/subscriptions/{subscription_id}"
        
        data = {
            "expirationDateTime": (datetime.now() + timedelta(days=3)).isoformat() + "Z"
        }
        
        result = await self._make_request("PATCH", url, json=data)
        return result is not None
    
    async def delete_subscription(self, subscription_id: str) -> bool:
        """Delete webhook subscription."""
        url = f"https://graph.microsoft.com/v1.0/subscriptions/{subscription_id}"
        
        result = await self._make_request("DELETE", url)
        return result is not None
    
    async def get_subscriptions(self) -> List[Dict]:
        """Get all active subscriptions."""
        url = "https://graph.microsoft.com/v1.0/subscriptions"
        
        result = await self._make_request("GET", url)
        return result.get("value", []) if result else []
    
    async def send_email(self, user_email: str, to_recipients: List[str], 
                        subject: str, body: str, is_html: bool = True) -> bool:
        """Send email notification."""
        url = f"https://graph.microsoft.com/v1.0/users/{user_email}/sendMail"
        
        recipients = [{"emailAddress": {"address": email}} for email in to_recipients]
        
        data = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "HTML" if is_html else "Text",
                    "content": body
                },
                "toRecipients": recipients
            }
        }
        
        result = await self._make_request("POST", url, json=data)
        return result is not None


class SubscriptionManager:
    """Manages Graph API webhook subscriptions."""
    
    def __init__(self, graph_client: GraphAPIClient):
        self.graph_client = graph_client
        self.active_subscriptions: Dict[str, Dict] = {}
    
    async def setup_user_monitoring(self, user_email: str, 
                                  notification_url: str) -> Optional[str]:
        """Set up email monitoring for a user."""
        try:
            subscription = await self.graph_client.create_webhook_subscription(
                user_email, notification_url
            )
            
            if subscription:
                subscription_id = subscription.get("id")
                self.active_subscriptions[user_email] = {
                    "subscription_id": subscription_id,
                    "expires_at": subscription.get("expirationDateTime"),
                    "notification_url": notification_url
                }
                logger.info(f"Created subscription for {user_email}: {subscription_id}")
                return subscription_id
            
        except Exception as e:
            logger.error(f"Failed to create subscription for {user_email}: {e}")
        
        return None
    
    async def renew_expiring_subscriptions(self):
        """Renew subscriptions that are about to expire."""
        current_time = datetime.now()
        renewal_threshold = timedelta(hours=12)  # Renew 12 hours before expiry
        
        for user_email, sub_info in self.active_subscriptions.items():
            expires_at = datetime.fromisoformat(
                sub_info["expires_at"].replace("Z", "+00:00")
            )
            
            if expires_at - current_time < renewal_threshold:
                success = await self.graph_client.renew_subscription(
                    sub_info["subscription_id"]
                )
                
                if success:
                    # Update expiration time
                    new_expires = current_time + timedelta(days=3)
                    sub_info["expires_at"] = new_expires.isoformat() + "Z"
                    logger.info(f"Renewed subscription for {user_email}")
                else:
                    logger.error(f"Failed to renew subscription for {user_email}")
    
    async def cleanup_expired_subscriptions(self):
        """Remove expired subscriptions from tracking."""
        current_time = datetime.now()
        expired_users = []
        
        for user_email, sub_info in self.active_subscriptions.items():
            expires_at = datetime.fromisoformat(
                sub_info["expires_at"].replace("Z", "+00:00")
            )
            
            if expires_at < current_time:
                expired_users.append(user_email)
        
        for user_email in expired_users:
            del self.active_subscriptions[user_email]
            logger.warning(f"Removed expired subscription for {user_email}")
