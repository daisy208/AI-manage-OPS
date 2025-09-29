"""Tests for authentication system."""
import pytest
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from src.database.models import Base
from src.auth.password import PasswordManager
from src.auth.jwt_handler import JWTHandler
from src.auth.service import AuthService
from src.auth.models import LoginRequest, RegisterRequest
from src.database.service import DatabaseService

# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

@pytest.fixture
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    await engine.dispose()

@pytest.fixture
async def test_session(test_engine):
    """Create test database session."""
    async_session = async_sessionmaker(test_engine, class_=AsyncSession)
    
    async with async_session() as session:
        yield session

@pytest.fixture
async def auth_service(test_session):
    """Create auth service for testing."""
    return AuthService(test_session)

class TestPasswordManager:
    """Test password hashing and verification."""
    
    def test_hash_password(self):
        """Test password hashing."""
        password = "test_password_123"
        hashed = PasswordManager.hash_password(password)
        
        # Hash should be different from original
        assert hashed != password
        # Should start with bcrypt identifier
        assert hashed.startswith('$2b$')
        # Should be proper length
        assert len(hashed) == 60
    
    def test_verify_password(self):
        """Test password verification."""
        password = "test_password_123"
        hashed = PasswordManager.hash_password(password)
        
        # Correct password should verify
        assert PasswordManager.verify_password(password, hashed) is True
        
        # Wrong password should not verify
        assert PasswordManager.verify_password("wrong_password", hashed) is False
    
    def test_needs_rehash(self):
        """Test rehash detection."""
        password = "test_password"
        
        # Hash with lower rounds (simulating old hash)
        import bcrypt
        old_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode()
        
        # Should need rehash
        assert PasswordManager.needs_rehash(old_hash, rounds=12) is True
        
        # New hash should not need rehash
        new_hash = PasswordManager.hash_password(password)
        assert PasswordManager.needs_rehash(new_hash, rounds=12) is False

class TestJWTHandler:
    """Test JWT token handling."""
    
    def test_create_access_token(self):
        """Test access token creation."""
        jwt_handler = JWTHandler()
        data = {"sub": "testuser", "user_id": 1}
        
        token = jwt_handler.create_access_token(data)
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Verify token
        payload = jwt_handler.verify_token(token)
        assert payload is not None
        assert payload["sub"] == "testuser"
        assert payload["user_id"] == 1
        assert payload["type"] == "access"
    
    def test_create_refresh_token(self):
        """Test refresh token creation."""
        jwt_handler = JWTHandler()
        data = {"sub": "testuser", "user_id": 1}
        
        token = jwt_handler.create_refresh_token(data)
        
        assert isinstance(token, str)
        
        # Verify token
        payload = jwt_handler.verify_token(token)
        assert payload is not None
        assert payload["type"] == "refresh"
    
    def test_verify_invalid_token(self):
        """Test verification of invalid token."""
        jwt_handler = JWTHandler()
        
        # Invalid token should return None
        assert jwt_handler.verify_token("invalid_token") is None
    
    def test_refresh_access_token(self):
        """Test access token refresh."""
        jwt_handler = JWTHandler()
        data = {"sub": "testuser", "user_id": 1, "email": "test@example.com"}
        
        # Create refresh token
        refresh_token = jwt_handler.create_refresh_token(data)
        
        # Use it to create new access token
        new_access_token = jwt_handler.refresh_access_token(refresh_token)
        
        assert new_access_token is not None
        
        # Verify new token
        payload = jwt_handler.verify_token(new_access_token)
        assert payload["sub"] == "testuser"
        assert payload["type"] == "access"

class TestAuthService:
    """Test authentication service."""
    
    @pytest.mark.asyncio
    async def test_register_user(self, auth_service):
        """Test user registration."""
        register_data = RegisterRequest(
            username="newuser",
            email="newuser@example.com",
            password="password123",
            confirm_password="password123"
        )
        
        user = await auth_service.register(register_data)
        
        assert user.username == "newuser"
        assert user.email == "newuser@example.com"
        assert user.is_active is True
        
        # Password should be hashed
        assert user.hashed_password != "password123"
        assert user.hashed_password.startswith('$2b$')
    
    @pytest.mark.asyncio
    async def test_register_duplicate_username(self, auth_service):
        """Test registration with duplicate username."""
        register_data = RegisterRequest(
            username="duplicate",
            email="user1@example.com",
            password="password123",
            confirm_password="password123"
        )
        
        # First registration should succeed
        await auth_service.register(register_data)
        
        # Second registration with same username should fail
        register_data.email = "user2@example.com"
        with pytest.raises(ValueError, match="Username already exists"):
            await auth_service.register(register_data)
    
    @pytest.mark.asyncio
    async def test_login_success(self, auth_service):
        """Test successful login."""
        # Register user first
        register_data = RegisterRequest(
            username="loginuser",
            email="loginuser@example.com",
            password="password123",
            confirm_password="password123"
        )
        await auth_service.register(register_data)
        
        # Login
        login_data = LoginRequest(username="loginuser", password="password123")
        token = await auth_service.login(login_data)
        
        assert token.access_token is not None
        assert token.refresh_token is not None
        assert token.token_type == "bearer"
        assert token.expires_in > 0
    
    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, auth_service):
        """Test login with invalid credentials."""
        login_data = LoginRequest(username="nonexistent", password="wrong")
        
        with pytest.raises(ValueError, match="Invalid credentials"):
            await auth_service.login(login_data)
    
    @pytest.mark.asyncio
    async def test_authenticate_user(self, auth_service):
        """Test user authentication."""
        # Register user
        register_data = RegisterRequest(
            username="authuser",
            email="authuser@example.com",
            password="password123",
            confirm_password="password123"
        )
        await auth_service.register(register_data)
        
        # Authenticate with username
        user = await auth_service.authenticate_user("authuser", "password123")
        assert user is not None
        assert user.username == "authuser"
        
        # Authenticate with email
        user = await auth_service.authenticate_user("authuser@example.com", "password123")
        assert user is not None
        assert user.username == "authuser"
        
        # Wrong password
        user = await auth_service.authenticate_user("authuser", "wrongpassword")
        assert user is None

if __name__ == "__main__":
    pytest.main([__file__])