"""Password hashing and verification using bcrypt."""
import bcrypt
from typing import Union

class PasswordManager:
    """Handles password hashing and verification using bcrypt."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt with automatic salt generation.
        
        Args:
            password: Plain text password to hash
            
        Returns:
            Hashed password as string
        """
        # Generate salt and hash password
        salt = bcrypt.gensalt(rounds=12)  # 12 rounds for good security/performance balance
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            password: Plain text password to verify
            hashed_password: Previously hashed password
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'), 
                hashed_password.encode('utf-8')
            )
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def needs_rehash(hashed_password: str, rounds: int = 12) -> bool:
        """
        Check if a password hash needs to be rehashed (e.g., due to updated rounds).
        
        Args:
            hashed_password: The hashed password to check
            rounds: Desired number of rounds
            
        Returns:
            True if rehashing is recommended
        """
        try:
            # Extract current rounds from hash
            current_rounds = int(hashed_password.split('$')[2])
            return current_rounds < rounds
        except (IndexError, ValueError):
            return True  # Invalid hash format, should rehash