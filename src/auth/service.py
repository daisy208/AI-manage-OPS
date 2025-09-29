"""Authentication service layer."""
from typing import Optional, Tuple
from datetime import timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from .password import PasswordManager
from .jwt_handler import JWTHandler
from .models import Token, LoginRequest, RegisterRequest, PasswordChangeRequest
from ..database.repository import UserRepository, AuditLogRepository
from ..database.models import User

class AuthService:
    """Authentication service handling login, registration, and token management."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.user_repo = UserRepository(session)
        self.audit_repo = AuditLogRepository(session)
        self.password_manager = PasswordManager()
        self.jwt_handler = JWTHandler()
    
    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user with username and password.
        
        Args:
            username: Username or email
            password: Plain text password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        # Try to find user by username or email
        user = await self.user_repo.get_by_username(username)
        if not user:
            user = await self.user_repo.get_by_email(username)
        
        if not user or not user.is_active:
            return None
        
        # Verify password
        if not self.password_manager.verify_password(password, user.hashed_password):
            return None
        
        # Check if password needs rehashing (security improvement)
        if self.password_manager.needs_rehash(user.hashed_password):
            new_hash = self.password_manager.hash_password(password)
            await self.user_repo.update(user.id, hashed_password=new_hash)
        
        return user
    
    async def login(self, login_data: LoginRequest, ip_address: str = None) -> Token:
        """
        Login user and create JWT tokens.
        
        Args:
            login_data: Login credentials
            ip_address: Client IP address for audit
            
        Returns:
            JWT tokens
            
        Raises:
            ValueError: If authentication fails
        """
        user = await self.authenticate_user(login_data.username, login_data.password)
        if not user:
            # Log failed login attempt
            await self.audit_repo.log_action(
                user_id=None,
                action='login_failed',
                resource_type='auth',
                details={'username': login_data.username},
                ip_address=ip_address
            )
            raise ValueError("Invalid credentials")
        
        # Create token data
        token_data = {
            "sub": user.username,
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        }
        
        # Generate tokens
        access_token = self.jwt_handler.create_access_token(token_data)
        refresh_token = self.jwt_handler.create_refresh_token(token_data)
        
        # Log successful login
        await self.audit_repo.log_action(
            user_id=user.id,
            action='login_success',
            resource_type='auth',
            ip_address=ip_address
        )
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.jwt_handler.access_token_expire_minutes * 60
        )
    
    async def register(self, register_data: RegisterRequest, ip_address: str = None) -> User:
        """
        Register a new user.
        
        Args:
            register_data: Registration data
            ip_address: Client IP address for audit
            
        Returns:
            Created user
            
        Raises:
            ValueError: If registration fails
        """
        # Validate passwords match
        if register_data.password != register_data.confirm_password:
            raise ValueError("Passwords do not match")
        
        # Check if username already exists
        existing_user = await self.user_repo.get_by_username(register_data.username)
        if existing_user:
            raise ValueError("Username already exists")
        
        # Check if email already exists
        existing_email = await self.user_repo.get_by_email(register_data.email)
        if existing_email:
            raise ValueError("Email already registered")
        
        # Hash password
        hashed_password = self.password_manager.hash_password(register_data.password)
        
        # Create user
        user = await self.user_repo.create(
            username=register_data.username,
            email=register_data.email,
            hashed_password=hashed_password
        )
        
        # Log registration
        await self.audit_repo.log_action(
            user_id=user.id,
            action='register',
            resource_type='user',
            resource_id=user.id,
            ip_address=ip_address
        )
        
        return user
    
    async def refresh_token(self, refresh_token: str) -> Optional[Token]:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            New token pair or None if invalid
        """
        new_access_token = self.jwt_handler.refresh_access_token(refresh_token)
        if not new_access_token:
            return None
        
        # For security, also generate a new refresh token
        payload = self.jwt_handler.verify_token(refresh_token)
        if not payload:
            return None
        
        token_data = {
            "sub": payload.get("sub"),
            "user_id": payload.get("user_id"),
            "username": payload.get("username"),
            "email": payload.get("email"),
            "is_admin": payload.get("is_admin", False)
        }
        
        new_refresh_token = self.jwt_handler.create_refresh_token(token_data)
        
        return Token(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_in=self.jwt_handler.access_token_expire_minutes * 60
        )
    
    async def change_password(self, user_id: int, password_data: PasswordChangeRequest) -> bool:
        """
        Change user password.
        
        Args:
            user_id: User ID
            password_data: Password change data
            
        Returns:
            True if successful
            
        Raises:
            ValueError: If password change fails
        """
        # Validate new passwords match
        if password_data.new_password != password_data.confirm_new_password:
            raise ValueError("New passwords do not match")
        
        # Get user
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Verify current password
        if not self.password_manager.verify_password(
            password_data.current_password, 
            user.hashed_password
        ):
            raise ValueError("Current password is incorrect")
        
        # Hash new password
        new_hashed_password = self.password_manager.hash_password(password_data.new_password)
        
        # Update password
        await self.user_repo.update(user_id, hashed_password=new_hashed_password)
        
        # Log password change
        await self.audit_repo.log_action(
            user_id=user_id,
            action='password_change',
            resource_type='user',
            resource_id=user_id
        )
        
        return True