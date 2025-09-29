"""Authentication data models."""
from typing import Optional
from pydantic import BaseModel, EmailStr

class TokenData(BaseModel):
    """Token payload data."""
    username: Optional[str] = None
    user_id: Optional[int] = None
    email: Optional[str] = None
    is_admin: bool = False

class UserInToken(BaseModel):
    """User information stored in JWT token."""
    id: int
    username: str
    email: EmailStr
    is_active: bool
    is_admin: bool = False

class Token(BaseModel):
    """Token response model."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class TokenRefresh(BaseModel):
    """Token refresh request model."""
    refresh_token: str

class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str

class RegisterRequest(BaseModel):
    """User registration request model."""
    username: str
    email: EmailStr
    password: str
    confirm_password: str

class PasswordChangeRequest(BaseModel):
    """Password change request model."""
    current_password: str
    new_password: str
    confirm_new_password: str