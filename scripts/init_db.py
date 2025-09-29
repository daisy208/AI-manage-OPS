#!/usr/bin/env python3
"""Initialize database with tables and sample data."""
import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from database.connection import init_db, get_db_session
from database.service import DatabaseService

async def create_sample_data():
    """Create sample data for development."""
    async with get_db_session() as session:
        db_service = DatabaseService(session)
        
        # Create sample user
        user = await db_service.create_user_with_audit(
            username="admin",
            email="admin@example.com",
            hashed_password="$2b$12$sample_hashed_password",  # In real app, hash properly
            ip_address="127.0.0.1"
        )
        
        # Create sample infrastructure
        infrastructure = await db_service.infrastructure.create(
            name="dev-cluster",
            provider="aws",
            region="us-west-2",
            environment="development",
            configuration={
                "instance_type": "t3.medium",
                "min_size": 1,
                "max_size": 3,
                "desired_capacity": 2
            },
            status="active"
        )
        
        # Create sample application
        application = await db_service.applications.create(
            name="ai-manage-ops-api",
            description="Main API service for AI-manage-OPS",
            repository_url="https://github.com/example/ai-manage-ops",
            branch="main",
            build_config={
                "dockerfile": "Dockerfile",
                "build_args": {}
            },
            runtime_config={
                "port": 8000,
                "replicas": 2,
                "resources": {
                    "cpu": "500m",
                    "memory": "512Mi"
                }
            },
            health_check_url="/health"
        )
        
        # Create sample deployment
        deployment = await db_service.create_deployment(
            user_id=user.id,
            application_id=application.id,
            infrastructure_id=infrastructure.id,
            version="v1.0.0",
            deployment_config={
                "strategy": "rolling",
                "max_unavailable": 1,
                "max_surge": 1
            }
        )
        
        # Store sample API key
        await db_service.store_api_key(
            user_id=user.id,
            service_name="aws",
            key_name="access_key_id",
            key_value="AKIA1234567890EXAMPLE"
        )
        
        print(f"✅ Sample data created:")
        print(f"   User: {user.username} (ID: {user.id})")
        print(f"   Infrastructure: {infrastructure.name} (ID: {infrastructure.id})")
        print(f"   Application: {application.name} (ID: {application.id})")
        print(f"   Deployment: {deployment.version} (ID: {deployment.id})")

async def main():
    """Main initialization function."""
    print("🚀 Initializing database...")
    
    try:
        # Create tables
        await init_db()
        print("✅ Database tables created")
        
        # Create sample data
        await create_sample_data()
        
        print("🎉 Database initialization complete!")
        
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())