"""Database service layer for business logic."""
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from .repository import (
    UserRepository, APIKeyRepository, DeploymentRepository, 
    AuditLogRepository, BaseRepository
)
from .models import User, APIKey, Deployment, Infrastructure, Application
from .connection import get_db_session
from ..auth.password import PasswordManager

class DatabaseService:
    """Main database service coordinating repositories."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.password_manager = PasswordManager()
        self.users = UserRepository(session)
        self.api_keys = APIKeyRepository(session)
        self.deployments = DeploymentRepository(session)
        self.audit_logs = AuditLogRepository(session)
        self.infrastructure = BaseRepository(session, Infrastructure)
        self.applications = BaseRepository(session, Application)
    
    async def create_user_with_audit(self, username: str, email: str, 
                                   password: str, ip_address: str = None) -> User:
        """Create user and log the action."""
        # Hash password using bcrypt
        hashed_password = self.password_manager.hash_password(password)
        
        user = await self.users.create(
            username=username,
            email=email,
            hashed_password=hashed_password
        )
        
        await self.audit_logs.log_action(
            user_id=user.id,
            action='create',
            resource_type='user',
            resource_id=user.id,
            ip_address=ip_address
        )
        
        return user
    
    async def store_api_key(self, user_id: int, service_name: str, 
                           key_name: str, key_value: str) -> APIKey:
        """Store encrypted API key."""
        # The encryption happens automatically in the EncryptedField
        api_key = await self.api_keys.create(
            user_id=user_id,
            service_name=service_name,
            key_name=key_name,
            encrypted_value=key_value  # Will be encrypted by EncryptedField
        )
        
        await self.audit_logs.log_action(
            user_id=user_id,
            action='create',
            resource_type='api_key',
            resource_id=api_key.id,
            details={'service_name': service_name, 'key_name': key_name}
        )
        
        return api_key
    
    async def create_deployment(self, user_id: int, application_id: int, 
                              infrastructure_id: int, version: str, 
                              deployment_config: Dict = None) -> Deployment:
        """Create deployment with audit trail."""
        deployment = await self.deployments.create(
            user_id=user_id,
            application_id=application_id,
            infrastructure_id=infrastructure_id,
            version=version,
            deployment_config=deployment_config or {}
        )
        
        await self.audit_logs.log_action(
            user_id=user_id,
            action='create',
            resource_type='deployment',
            resource_id=deployment.id,
            details={
                'application_id': application_id,
                'infrastructure_id': infrastructure_id,
                'version': version
            }
        )
        
        return deployment
    
    async def update_deployment_status(self, deployment_id: int, status: str, 
                                     logs: str = None, error_message: str = None) -> Optional[Deployment]:
        """Update deployment status with logging."""
        deployment = await self.deployments.update(
            deployment_id,
            status=status,
            logs=logs,
            error_message=error_message
        )
        
        if deployment:
            await self.audit_logs.log_action(
                user_id=deployment.user_id,
                action='update',
                resource_type='deployment',
                resource_id=deployment_id,
                details={'status': status, 'has_error': bool(error_message)}
            )
        
        return deployment

# Convenience function for getting database service
async def get_db_service() -> DatabaseService:
    """Get database service instance."""
    async with get_db_session() as session:
        return DatabaseService(session)