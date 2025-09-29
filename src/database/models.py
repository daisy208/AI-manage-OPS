"""Database models for AI-manage-OPS."""
from datetime import datetime
from typing import Optional
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from .encryption import EncryptedField

Base = declarative_base()

class TimestampMixin:
    """Mixin for created_at and updated_at timestamps."""
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

class User(Base, TimestampMixin):
    """User model for authentication and authorization."""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    # Relationships
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    deployments = relationship("Deployment", back_populates="user")

class APIKey(Base, TimestampMixin):
    """API keys with encryption for external services."""
    __tablename__ = 'api_keys'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    service_name = Column(String(100), nullable=False)  # e.g., 'aws', 'gcp', 'azure'
    key_name = Column(String(100), nullable=False)      # e.g., 'access_key', 'secret_key'
    encrypted_value = Column(EncryptedField(500), nullable=False)  # Encrypted API key
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")

class Infrastructure(Base, TimestampMixin):
    """Infrastructure configuration and state."""
    __tablename__ = 'infrastructure'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, index=True)
    provider = Column(String(50), nullable=False)  # aws, gcp, azure
    region = Column(String(50), nullable=False)
    environment = Column(String(50), nullable=False)  # dev, staging, prod
    configuration = Column(JSON, nullable=False)  # Infrastructure as code config
    state = Column(Text)  # Current state (e.g., Terraform state)
    status = Column(String(50), default='pending')  # pending, deploying, active, error
    
    # Relationships
    deployments = relationship("Deployment", back_populates="infrastructure")

class Application(Base, TimestampMixin):
    """Application definitions and configurations."""
    __tablename__ = 'applications'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text)
    repository_url = Column(String(500))
    branch = Column(String(100), default='main')
    build_config = Column(JSON)  # Build configuration
    runtime_config = Column(JSON)  # Runtime configuration
    health_check_url = Column(String(500))
    
    # Relationships
    deployments = relationship("Deployment", back_populates="application")

class Deployment(Base, TimestampMixin):
    """Deployment records and history."""
    __tablename__ = 'deployments'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    application_id = Column(Integer, ForeignKey('applications.id'), nullable=False)
    infrastructure_id = Column(Integer, ForeignKey('infrastructure.id'), nullable=False)
    
    version = Column(String(100), nullable=False)
    status = Column(String(50), default='pending')  # pending, deploying, success, failed, rollback
    deployment_config = Column(JSON)  # Deployment-specific configuration
    logs = Column(Text)  # Deployment logs
    error_message = Column(Text)  # Error details if deployment failed
    
    deployed_at = Column(DateTime)
    rollback_deployment_id = Column(Integer, ForeignKey('deployments.id'))
    
    # Relationships
    user = relationship("User", back_populates="deployments")
    application = relationship("Application", back_populates="deployments")
    infrastructure = relationship("Infrastructure", back_populates="deployments")
    rollback_deployment = relationship("Deployment", remote_side=[id])

class MonitoringAlert(Base, TimestampMixin):
    """Monitoring alerts and notifications."""
    __tablename__ = 'monitoring_alerts'
    
    id = Column(Integer, primary_key=True, index=True)
    deployment_id = Column(Integer, ForeignKey('deployments.id'), nullable=False)
    alert_type = Column(String(50), nullable=False)  # cpu, memory, disk, network, custom
    severity = Column(String(20), nullable=False)    # low, medium, high, critical
    message = Column(Text, nullable=False)
    threshold_value = Column(String(100))
    current_value = Column(String(100))
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime)
    
    # Relationships
    deployment = relationship("Deployment")

class AuditLog(Base, TimestampMixin):
    """Audit trail for all system operations."""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String(100), nullable=False)  # create, update, delete, deploy, rollback
    resource_type = Column(String(50), nullable=False)  # user, deployment, infrastructure
    resource_id = Column(Integer)
    details = Column(JSON)  # Additional context about the action
    ip_address = Column(String(45))  # IPv4 or IPv6
    user_agent = Column(String(500))
    
    # Relationships
    user = relationship("User")