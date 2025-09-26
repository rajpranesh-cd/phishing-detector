"""
Data encryption and security utilities.
"""
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from typing import Union

from ..utils.config import get_settings

settings = get_settings()

class DataEncryption:
    """
    Handle sensitive data encryption/decryption.
    """
    
    def __init__(self):
        self.key = self._get_or_create_key()
        self.cipher = Fernet(self.key)
    
    def _get_or_create_key(self) -> bytes:
        """
        Get encryption key from environment or generate new one.
        """
        if hasattr(settings, 'ENCRYPTION_KEY') and settings.ENCRYPTION_KEY:
            return settings.ENCRYPTION_KEY.encode()
        
        # Generate key from password
        password = settings.SECRET_KEY.encode()
        salt = b'phishing_detector_salt'  # In production, use random salt
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt(self, data: Union[str, bytes]) -> str:
        """
        Encrypt sensitive data.
        """
        if isinstance(data, str):
            data = data.encode()
        
        encrypted = self.cipher.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt sensitive data.
        """
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted = self.cipher.decrypt(encrypted_bytes)
        return decrypted.decode()
    
    def encrypt_email_content(self, content: str) -> str:
        """
        Encrypt email content for storage.
        """
        return self.encrypt(content)
    
    def decrypt_email_content(self, encrypted_content: str) -> str:
        """
        Decrypt email content for analysis.
        """
        return self.decrypt(encrypted_content)

class SecureStorage:
    """
    Secure storage utilities for sensitive data.
    """
    
    def __init__(self):
        self.encryption = DataEncryption()
    
    def store_sensitive_data(self, data: dict, table: str, record_id: str):
        """
        Store sensitive data with encryption.
        """
        from ..utils.database import get_db_connection
        
        # Encrypt sensitive fields
        encrypted_data = {}
        for key, value in data.items():
            if self._is_sensitive_field(key):
                encrypted_data[key] = self.encryption.encrypt(str(value))
            else:
                encrypted_data[key] = value
        
        # Store in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Dynamic query building (simplified for example)
        fields = list(encrypted_data.keys())
        placeholders = ', '.join(['%s'] * len(fields))
        
        cursor.execute(f"""
            INSERT INTO {table} ({', '.join(fields)})
            VALUES ({placeholders})
        """, list(encrypted_data.values()))
        
        conn.commit()
        conn.close()
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """
        Determine if field contains sensitive data.
        """
        sensitive_fields = [
            'email_body', 'email_content', 'attachment_content',
            'personal_info', 'credentials', 'api_keys'
        ]
        return field_name.lower() in sensitive_fields

# Global instances
data_encryption = DataEncryption()
secure_storage = SecureStorage()
