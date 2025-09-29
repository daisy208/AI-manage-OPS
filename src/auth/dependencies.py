"""Authentication dependencies for FastAPI."""
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from .jwt_handler import JWTHandler
from .models import UserInToken
from ..database.connection import get_db_session
from ..database.repository import UserRepository

# Security scheme
security = HTTPBearer()
jwt_handler = JWTHandler()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: AsyncSession = Depends(get_db_session)
) -> UserInToken:
    """
    Get current authenticated user from JWT token.
    
    Args:
        credentials: HTTP Bearer token
        session: Database session
        
    Returns:
        Current user information
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Verify token
        payload = jwt_handler.verify_token(credentials.credentials)
        if payload is None:
            raise credentials_exception
        
        # Extract user info
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
            
    except Exception:
        raise credentials_exception
    
    # Get user from database
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)
    
    if user is None:
        raise credentials_exception
    
    return UserInToken(
        id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        is_admin=user.is_admin
    )

async def get_current_active_user(
    current_user: UserInToken = Depends(get_current_user)
) -> UserInToken:
    """
    Get current active user (must be active).
    
    Args:
        current_user: Current user from token
        
    Returns:
        Active user information
        
    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Inactive user"
        )
    return current_user

async def get_admin_user(
    current_user: UserInToken = Depends(get_current_active_user)
) -> UserInToken:
    """
    Get current user if they are an admin.
    
    Args:
        current_user: Current active user
        
    Returns:
        Admin user information
        
    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[UserInToken]:
    """
    Get user if token is provided, otherwise return None.
    Useful for endpoints that work for both authenticated and anonymous users.
    
    Args:
        credentials: Optional HTTP Bearer token
        
    Returns:
        User information or None
    """
    if not credentials:
        return None
    
    try:
        payload = jwt_handler.verify_token(credentials.credentials)
        if payload is None:
            return None
        
        return UserInToken(
            id=payload.get("user_id"),
            username=payload.get("sub"),
            email=payload.get("email"),
            is_active=True,
            is_admin=payload.get("is_admin", False)
        )
    except Exception:
        return None