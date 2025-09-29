"""Field encryption utilities for sensitive data."""
import os
import base64
from typing import Any, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import TypeDecorator, String
from dotenv import load_dotenv

load_dotenv()

class FieldEncryption:
    """Handles field-level encryption for sensitive data."""
    
    def __init__(self):
        self._fernet = None
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Initialize encryption with key from environment."""
        encryption_key = os.getenv('ENCRYPTION_KEY')
        
        if not encryption_key:
            # Generate a key if none exists (for development)
            # In production, this should be set as an environment variable
            password = os.getenv('ENCRYPTION_PASSWORD', 'default-dev-password').encode()
            salt = os.getenv('ENCRYPTION_SALT', 'default-salt').encode()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            self._fernet = Fernet(key)
        else:
            self._fernet = Fernet(encryption_key.encode())
    
    def encrypt(self, value: str) -> str:
        """Encrypt a string value."""
        if not value:
            return value
        return self._fernet.encrypt(value.encode()).decode()
    
    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt an encrypted string value."""
        if not encrypted_value:
            return encrypted_value
        return self._fernet.decrypt(encrypted_value.encode()).decode()

# Global encryption instance
_encryption = FieldEncryption()

class EncryptedField(TypeDecorator):
    """SQLAlchemy custom type for encrypted fields."""
    
    impl = String
    cache_ok = True
    
    def process_bind_param(self, value: Optional[str], dialect) -> Optional[str]:
        """Encrypt value before storing in database."""
        if value is not None:
            return _encryption.encrypt(value)
        return value
    
    def process_result_value(self, value: Optional[str], dialect) -> Optional[str]:
        """Decrypt value when retrieving from database."""
        if value is not None:
            return _encryption.decrypt(value)
        return value

def encrypt_field(value: str) -> str:
    """Utility function to encrypt a field value."""
    return _encryption.encrypt(value)

def decrypt_field(encrypted_value: str) -> str:
    """Utility function to decrypt a field value."""
    return _encryption.decrypt(encrypted_value)