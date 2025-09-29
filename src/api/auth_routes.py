"""Authentication API routes."""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth.service import AuthService
from ..auth.models import Token, LoginRequest, RegisterRequest, TokenRefresh, PasswordChangeRequest
from ..auth.dependencies import get_current_active_user, get_current_user
from ..database.connection import get_db_session

router = APIRouter(prefix="/auth", tags=["authentication"])

def get_client_ip(request: Request) -> str:
    """Extract client IP address from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host

@router.post("/login", response_model=Token)
async def login(
    login_data: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session)
):
    """
    Login with username/email and password.
    Returns JWT access and refresh tokens.
    """
    auth_service = AuthService(session)
    client_ip = get_client_ip(request)
    
    try:
        token = await auth_service.login(login_data, ip_address=client_ip)
        return token
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    register_data: RegisterRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session)
):
    """
    Register a new user account.
    """
    auth_service = AuthService(session)
    client_ip = get_client_ip(request)
    
    try:
        user = await auth_service.register(register_data, ip_address=client_ip)
        return {
            "message": "User registered successfully",
            "user_id": user.id,
            "username": user.username
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/refresh", response_model=Token)
async def refresh_token(
    token_data: TokenRefresh,
    session: AsyncSession = Depends(get_db_session)
):
    """
    Refresh access token using refresh token.
    """
    auth_service = AuthService(session)
    
    token = await auth_service.refresh_token(token_data.refresh_token)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    return token

@router.post("/change-password")
async def change_password(
    password_data: PasswordChangeRequest,
    current_user = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session)
):
    """
    Change user password.
    """
    auth_service = AuthService(session)
    
    try:
        await auth_service.change_password(current_user.id, password_data)
        return {"message": "Password changed successfully"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/me")
async def get_current_user_info(current_user = Depends(get_current_user)):
    """
    Get current user information from token.
    """
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_active": current_user.is_active,
        "is_admin": current_user.is_admin
    }

@router.post("/logout")
async def logout():
    """
    Logout endpoint. 
    Note: With JWT, logout is typically handled client-side by removing the token.
    For server-side logout, you would need to implement a token blacklist.
    """
    return {"message": "Logged out successfully"}

@router.get("/validate")
async def validate_token(current_user = Depends(get_current_user)):
    """
    Validate current token and return user info.
    """
    return {
        "valid": True,
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "is_admin": current_user.is_admin
        }
    }