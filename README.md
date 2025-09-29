# AI-manage-OPS - Database Layer

A robust database layer built with PostgreSQL, SQLAlchemy ORM, Alembic migrations, and field-level encryption for sensitive data.

## Features

### 🗄️ Database Architecture
- **PostgreSQL** for production scalability and reliability
- **SQLAlchemy 2.0** with async support for modern Python applications
- **Connection pooling** for optimal performance
- **Alembic migrations** for schema evolution and version control

### 🔐 Security
- **Field-level encryption** for sensitive data (API keys, secrets)
- **Fernet encryption** with PBKDF2 key derivation
- **Audit logging** for all database operations
- **Secure password hashing** support

### 📊 Data Models
- **Users** - Authentication and authorization
- **API Keys** - Encrypted storage of external service credentials
- **Infrastructure** - Cloud infrastructure configurations
- **Applications** - Application definitions and configs
- **Deployments** - Deployment history and status tracking
- **Monitoring Alerts** - System health and alerting
- **Audit Logs** - Complete audit trail

### 🏗️ Architecture Patterns
- **Repository Pattern** for clean data access
- **Service Layer** for business logic
- **Async/Await** throughout for high performance
- **Type hints** for better code quality

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set Up Environment
```bash
cp .env.example .env
# Edit .env with your database credentials and encryption keys
```

### 3. Initialize Database
```bash
# Create tables and sample data
python scripts/init_db.py
```

### 4. Run Migrations
```bash
# Initialize Alembic (first time only)
alembic init alembic

# Generate migration
python scripts/generate_migration.py "Initial schema"

# Apply migrations
alembic upgrade head
```

## Usage Examples

### Basic Database Operations
```python
from src.database.connection import get_db_session
from src.database.service import DatabaseService

async def example_usage():
    async with get_db_session() as session:
        db_service = DatabaseService(session)
        
        # Create user
        user = await db_service.create_user_with_audit(
            username="john_doe",
            email="john@example.com",
            hashed_password="$2b$12$...",
            ip_address="192.168.1.1"
        )
        
        # Store encrypted API key
        api_key = await db_service.store_api_key(
            user_id=user.id,
            service_name="aws",
            key_name="access_key_id",
            key_value="AKIA1234567890EXAMPLE"
        )
        
        # Create deployment
        deployment = await db_service.create_deployment(
            user_id=user.id,
            application_id=1,
            infrastructure_id=1,
            version="v1.2.3"
        )
```

### Working with Encrypted Fields
```python
from src.database.models import APIKey
from src.database.encryption import encrypt_field, decrypt_field

# Manual encryption (usually handled automatically)
encrypted_value = encrypt_field("my-secret-key")
decrypted_value = decrypt_field(encrypted_value)

# Automatic encryption in models
api_key = APIKey(
    user_id=1,
    service_name="aws",
    key_name="secret_key",
    encrypted_value="my-secret-key"  # Automatically encrypted
)
# When retrieved, encrypted_value is automatically decrypted
```

### Repository Pattern Usage
```python
async with get_db_session() as session:
    user_repo = UserRepository(session)
    
    # Find user by username
    user = await user_repo.get_by_username("admin")
    
    # Get user's deployments
    deployment_repo = DeploymentRepository(session)
    deployments = await deployment_repo.get_user_deployments(
        user_id=user.id,
        status="success"
    )
```

## Database Schema

### Core Tables
- `users` - User accounts and authentication
- `api_keys` - Encrypted external service credentials
- `infrastructure` - Cloud infrastructure definitions
- `applications` - Application configurations
- `deployments` - Deployment records and history
- `monitoring_alerts` - System alerts and notifications
- `audit_logs` - Complete audit trail

### Key Relationships
- Users have many API keys and deployments
- Deployments link users, applications, and infrastructure
- All operations are logged in audit_logs

## Security Features

### Encryption
- **Fernet symmetric encryption** for field-level security
- **PBKDF2 key derivation** with configurable iterations
- **Environment-based key management**
- **Automatic encryption/decryption** in SQLAlchemy models

### Audit Trail
- **Complete operation logging** with user context
- **IP address and user agent tracking**
- **Resource-level change tracking**
- **Searchable audit history**

## Migration Management

### Generate Migration
```bash
python scripts/generate_migration.py "Add new column to users table"
```

### Apply Migrations
```bash
# Upgrade to latest
alembic upgrade head

# Upgrade to specific revision
alembic upgrade abc123

# Downgrade
alembic downgrade -1
```

### Migration Best Practices
- Always review generated migrations before applying
- Test migrations on staging environment first
- Use descriptive migration messages
- Never edit existing migration files

## Testing

Run the test suite:
```bash
pytest tests/test_database.py -v
```

Tests cover:
- Encryption/decryption functionality
- Repository operations
- Service layer business logic
- Audit trail creation
- Database relationships

## Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/ai_manage_ops
DATABASE_DEBUG=false

# Encryption
ENCRYPTION_KEY=your-base64-fernet-key
ENCRYPTION_PASSWORD=your-secure-password
ENCRYPTION_SALT=your-secure-salt

# Application
SECRET_KEY=your-app-secret-key
DEBUG=false
```

### Connection Pool Settings
- **Pool size**: 10 connections
- **Max overflow**: 20 connections
- **Pre-ping**: Enabled for connection health checks
- **Async engine**: Full async/await support

## Performance Considerations

### Indexing Strategy
- Primary keys on all tables
- Unique indexes on usernames and emails
- Composite indexes on frequently queried columns
- Foreign key indexes for join performance

### Query Optimization
- **Eager loading** for related data using `selectinload`
- **Pagination** support in repository methods
- **Connection pooling** for concurrent requests
- **Async operations** throughout the stack

## Production Deployment

### Database Setup
1. Create PostgreSQL database
2. Set up connection pooling (PgBouncer recommended)
3. Configure backup strategy
4. Set up monitoring and alerting

### Security Checklist
- [ ] Use strong encryption keys
- [ ] Enable SSL/TLS for database connections
- [ ] Restrict database access by IP
- [ ] Regular security updates
- [ ] Monitor audit logs for suspicious activity

### Monitoring
- Connection pool metrics
- Query performance
- Encryption/decryption performance
- Audit log growth
- Failed authentication attempts

This database layer provides a solid foundation for the AI-manage-OPS platform with enterprise-grade security, scalability, and maintainability features.