"""Repository pattern for database operations."""
from typing import List, Optional, Dict, Any
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from .models import User, APIKey, Infrastructure, Application, Deployment, MonitoringAlert, AuditLog

class BaseRepository:
    """Base repository with common CRUD operations."""
    
    def __init__(self, session: AsyncSession, model_class):
        self.session = session
        self.model_class = model_class
    
    async def create(self, **kwargs) -> Any:
        """Create a new record."""
        instance = self.model_class(**kwargs)
        self.session.add(instance)
        await self.session.flush()
        await self.session.refresh(instance)
        return instance
    
    async def get_by_id(self, id: int) -> Optional[Any]:
        """Get record by ID."""
        result = await self.session.execute(
            select(self.model_class).where(self.model_class.id == id)
        )
        return result.scalar_one_or_none()
    
    async def get_all(self, limit: int = 100, offset: int = 0) -> List[Any]:
        """Get all records with pagination."""
        result = await self.session.execute(
            select(self.model_class).limit(limit).offset(offset)
        )
        return result.scalars().all()
    
    async def update(self, id: int, **kwargs) -> Optional[Any]:
        """Update record by ID."""
        await self.session.execute(
            update(self.model_class)
            .where(self.model_class.id == id)
            .values(**kwargs)
        )
        return await self.get_by_id(id)
    
    async def delete(self, id: int) -> bool:
        """Delete record by ID."""
        result = await self.session.execute(
            delete(self.model_class).where(self.model_class.id == id)
        )
        return result.rowcount > 0

class UserRepository(BaseRepository):
    """Repository for User operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, User)
    
    async def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        result = await self.session.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none()
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        result = await self.session.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

class APIKeyRepository(BaseRepository):
    """Repository for API Key operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, APIKey)
    
    async def get_user_keys(self, user_id: int, service_name: str = None) -> List[APIKey]:
        """Get API keys for a user, optionally filtered by service."""
        query = select(APIKey).where(APIKey.user_id == user_id, APIKey.is_active == True)
        if service_name:
            query = query.where(APIKey.service_name == service_name)
        
        result = await self.session.execute(query)
        return result.scalars().all()

class DeploymentRepository(BaseRepository):
    """Repository for Deployment operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, Deployment)
    
    async def get_with_relations(self, deployment_id: int) -> Optional[Deployment]:
        """Get deployment with all related data."""
        result = await self.session.execute(
            select(Deployment)
            .options(
                selectinload(Deployment.user),
                selectinload(Deployment.application),
                selectinload(Deployment.infrastructure)
            )
            .where(Deployment.id == deployment_id)
        )
        return result.scalar_one_or_none()
    
    async def get_user_deployments(self, user_id: int, status: str = None) -> List[Deployment]:
        """Get deployments for a user, optionally filtered by status."""
        query = select(Deployment).where(Deployment.user_id == user_id)
        if status:
            query = query.where(Deployment.status == status)
        
        result = await self.session.execute(query.order_by(Deployment.created_at.desc()))
        return result.scalars().all()

class AuditLogRepository(BaseRepository):
    """Repository for Audit Log operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, AuditLog)
    
    async def log_action(self, user_id: int, action: str, resource_type: str, 
                        resource_id: int = None, details: Dict = None, 
                        ip_address: str = None, user_agent: str = None) -> AuditLog:
        """Create an audit log entry."""
        return await self.create(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
    
    async def get_user_activity(self, user_id: int, limit: int = 50) -> List[AuditLog]:
        """Get recent activity for a user."""
        result = await self.session.execute(
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
        )
        return result.scalars().all()