"""Tests for database layer."""
import pytest
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from src.database.models import Base, User, APIKey
from src.database.service import DatabaseService
from src.database.encryption import encrypt_field, decrypt_field

# Test database URL (use in-memory SQLite for tests)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

@pytest.fixture
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    
    # Create tables
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
async def db_service(test_session):
    """Create database service for testing."""
    return DatabaseService(test_session)

class TestEncryption:
    """Test encryption functionality."""
    
    def test_encrypt_decrypt(self):
        """Test field encryption and decryption."""
        original_value = "secret-api-key-12345"
        
        # Encrypt
        encrypted = encrypt_field(original_value)
        assert encrypted != original_value
        assert len(encrypted) > len(original_value)
        
        # Decrypt
        decrypted = decrypt_field(encrypted)
        assert decrypted == original_value
    
    def test_empty_values(self):
        """Test encryption with empty values."""
        assert encrypt_field("") == ""
        assert decrypt_field("") == ""
        assert encrypt_field(None) is None
        assert decrypt_field(None) is None

class TestUserRepository:
    """Test user repository operations."""
    
    @pytest.mark.asyncio
    async def test_create_user(self, db_service):
        """Test user creation."""
        user = await db_service.users.create(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_password_123"
        )
        
        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.is_admin is False
    
    @pytest.mark.asyncio
    async def test_get_user_by_username(self, db_service):
        """Test getting user by username."""
        # Create user
        await db_service.users.create(
            username="findme",
            email="findme@example.com",
            hashed_password="password"
        )
        
        # Find user
        user = await db_service.users.get_by_username("findme")
        assert user is not None
        assert user.username == "findme"
        
        # Test non-existent user
        user = await db_service.users.get_by_username("notfound")
        assert user is None

class TestAPIKeyRepository:
    """Test API key repository operations."""
    
    @pytest.mark.asyncio
    async def test_store_encrypted_api_key(self, db_service):
        """Test storing encrypted API key."""
        # Create user first
        user = await db_service.users.create(
            username="keyuser",
            email="keyuser@example.com",
            hashed_password="password"
        )
        
        # Store API key
        api_key = await db_service.store_api_key(
            user_id=user.id,
            service_name="aws",
            key_name="access_key_id",
            key_value="AKIA1234567890EXAMPLE"
        )
        
        assert api_key.id is not None
        assert api_key.user_id == user.id
        assert api_key.service_name == "aws"
        assert api_key.key_name == "access_key_id"
        # The encrypted_value should be decrypted automatically when accessed
        assert api_key.encrypted_value == "AKIA1234567890EXAMPLE"
    
    @pytest.mark.asyncio
    async def test_get_user_keys(self, db_service):
        """Test getting user's API keys."""
        # Create user
        user = await db_service.users.create(
            username="multikey",
            email="multikey@example.com",
            hashed_password="password"
        )
        
        # Store multiple keys
        await db_service.store_api_key(user.id, "aws", "access_key", "key1")
        await db_service.store_api_key(user.id, "aws", "secret_key", "key2")
        await db_service.store_api_key(user.id, "gcp", "service_account", "key3")
        
        # Get all keys
        all_keys = await db_service.api_keys.get_user_keys(user.id)
        assert len(all_keys) == 3
        
        # Get AWS keys only
        aws_keys = await db_service.api_keys.get_user_keys(user.id, "aws")
        assert len(aws_keys) == 2
        assert all(key.service_name == "aws" for key in aws_keys)

class TestDeploymentOperations:
    """Test deployment operations."""
    
    @pytest.mark.asyncio
    async def test_create_deployment_with_audit(self, db_service):
        """Test deployment creation with audit trail."""
        # Create prerequisites
        user = await db_service.users.create(
            username="deployer",
            email="deployer@example.com",
            hashed_password="password"
        )
        
        infrastructure = await db_service.infrastructure.create(
            name="test-infra",
            provider="aws",
            region="us-west-2",
            environment="test",
            configuration={"type": "k8s"}
        )
        
        application = await db_service.applications.create(
            name="test-app",
            description="Test application",
            repository_url="https://github.com/test/app"
        )
        
        # Create deployment
        deployment = await db_service.create_deployment(
            user_id=user.id,
            application_id=application.id,
            infrastructure_id=infrastructure.id,
            version="v1.0.0",
            deployment_config={"strategy": "rolling"}
        )
        
        assert deployment.id is not None
        assert deployment.status == "pending"
        assert deployment.version == "v1.0.0"
        
        # Check audit log was created
        audit_logs = await db_service.audit_logs.get_user_activity(user.id)
        assert len(audit_logs) >= 1
        deployment_log = next(
            (log for log in audit_logs if log.resource_type == "deployment"), 
            None
        )
        assert deployment_log is not None
        assert deployment_log.action == "create"

if __name__ == "__main__":
    pytest.main([__file__])