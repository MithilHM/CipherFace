"""
Database Initialization Script

This script handles complete database setup including:
1. pgcrypto extension creation
2. ENUM type creation
3. Table creation with all constraints
4. Trigger creation for audit log immutability
5. Index creation for performance
6. Seed data for initial setup

Usage:
    poetry run python -m homomorphic_face_encryption.database.init_db

For Docker:
    docker exec -it app python -m homomorphic_face_encryption.database.init_db
"""

import logging
import os
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from .models import (
    AuditAction,
    AuditLog,
    Base,
    BiometricTemplate,
    ConsentPurpose,
    ConsentRecord,
    User,
    engine,
    SessionLocal,
)
from .encryption_utils import setup_pgcrypto, hash_consent_text

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def create_extension():
    """Create pgcrypto extension if not exists."""
    logger.info("Setting up pgcrypto extension...")
    try:
        setup_pgcrypto(engine)
        logger.info("✓ pgcrypto extension ready")
    except Exception as e:
        logger.warning(f"Could not create pgcrypto extension: {e}")
        logger.info("This may be fine if extension already exists or requires superuser")


def create_enum_types():
    """
    Create PostgreSQL ENUM types if they don't exist.
    
    SQLAlchemy creates these automatically, but explicit creation
    gives us more control and better error messages.
    """
    logger.info("Creating ENUM types...")
    
    with engine.connect() as conn:
        # Check and create consent_purpose enum
        try:
            conn.execute(text("""
                DO $$ BEGIN
                    CREATE TYPE consent_purpose AS ENUM (
                        'AUTHENTICATION',
                        'ACCESS_CONTROL', 
                        'AUDIT'
                    );
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            logger.info("✓ consent_purpose ENUM ready")
        except ProgrammingError as e:
            logger.debug(f"consent_purpose already exists: {e}")
        
        # Check and create audit_action enum
        try:
            conn.execute(text("""
                DO $$ BEGIN
                    CREATE TYPE audit_action AS ENUM (
                        'ENROLL',
                        'AUTHENTICATE_SUCCESS',
                        'AUTHENTICATE_FAIL',
                        'CONSENT_GRANT',
                        'CONSENT_REVOKE',
                        'DATA_DELETE',
                        'DATA_EXPORT',
                        'SESSION_INVALIDATE',
                        'KEY_ROTATION'
                    );
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            logger.info("✓ audit_action ENUM ready")
        except ProgrammingError as e:
            logger.debug(f"audit_action already exists: {e}")
        
        conn.commit()


def create_update_timestamp_function():
    """
    Create PostgreSQL function for automatic updated_at timestamp.
    
    This trigger function updates the updated_at column whenever
    a row is modified.
    """
    logger.info("Creating update_timestamp function...")
    
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = CURRENT_TIMESTAMP;
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        """))
        conn.commit()
    
    logger.info("✓ update_updated_at_column function ready")


def create_audit_log_immutability_trigger():
    """
    Create trigger to prevent UPDATE operations on audit_logs.
    
    This provides database-level protection in addition to the
    Python-level event listener in models.py.
    
    DPDP Compliance:
    - Ensures audit trail cannot be tampered with
    - Required for breach investigation and compliance audits
    """
    logger.info("Creating audit log immutability trigger...")
    
    with engine.connect() as conn:
        # Create the trigger function
        conn.execute(text("""
            CREATE OR REPLACE FUNCTION prevent_audit_log_update()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION 'UPDATE operations on audit_logs are prohibited. Audit records are immutable for compliance.';
            END;
            $$ language 'plpgsql';
        """))
        
        # Drop existing trigger if exists (for idempotency)
        conn.execute(text("""
            DROP TRIGGER IF EXISTS trigger_prevent_audit_update ON audit_logs;
        """))
        
        # Create the trigger (only after table exists)
        # This will be called after create_tables()
        conn.commit()
    
    logger.info("✓ Audit log immutability function ready")


def create_tables():
    """
    Create all database tables using SQLAlchemy metadata.
    
    This is idempotent - safe to run multiple times.
    """
    logger.info("Creating database tables...")
    
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("✓ All tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create tables: {e}")
        raise


def apply_audit_trigger():
    """Apply the audit log immutability trigger after table creation."""
    logger.info("Applying audit log trigger...")
    
    with engine.connect() as conn:
        try:
            conn.execute(text("""
                CREATE TRIGGER trigger_prevent_audit_update
                BEFORE UPDATE ON audit_logs
                FOR EACH ROW
                EXECUTE FUNCTION prevent_audit_log_update();
            """))
            conn.commit()
            logger.info("✓ Audit log immutability trigger applied")
        except ProgrammingError as e:
            if "already exists" in str(e):
                logger.debug("Trigger already exists")
            else:
                logger.warning(f"Could not create trigger: {e}")


def create_updated_at_triggers():
    """Create triggers for automatic updated_at timestamp updates."""
    logger.info("Creating updated_at triggers...")
    
    tables_with_updated_at = ["users", "biometric_templates"]
    
    with engine.connect() as conn:
        for table in tables_with_updated_at:
            try:
                trigger_name = f"trigger_update_{table}_updated_at"
                
                # Drop if exists for idempotency
                conn.execute(text(f"""
                    DROP TRIGGER IF EXISTS {trigger_name} ON {table};
                """))
                
                # Create trigger
                conn.execute(text(f"""
                    CREATE TRIGGER {trigger_name}
                    BEFORE UPDATE ON {table}
                    FOR EACH ROW
                    EXECUTE FUNCTION update_updated_at_column();
                """))
                
                logger.info(f"✓ Updated_at trigger for {table} ready")
            except ProgrammingError as e:
                logger.warning(f"Could not create trigger for {table}: {e}")
        
        conn.commit()


def create_performance_indexes():
    """
    Create additional indexes for query performance.
    
    These are created CONCURRENTLY for production safety
    (doesn't lock the table during creation).
    """
    logger.info("Creating performance indexes...")
    
    indexes = [
        # Consent verification: frequently queried with user_id + purpose + is_revoked
        """
        CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_consent_active_lookup
        ON consent_records (user_id, purpose)
        WHERE is_revoked = false;
        """,
        
        # Audit log date range queries for breach investigation
        """
        CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_audit_date_range
        ON audit_logs (timestamp DESC);
        """,
        
        # Active templates for a user (enrollment/verification)
        """
        CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_template_active_user
        ON biometric_templates (user_id)
        WHERE is_active = true;
        """,
    ]
    
    with engine.connect() as conn:
        # CONCURRENTLY requires autocommit mode
        conn.execution_options(isolation_level="AUTOCOMMIT")
        
        for idx_sql in indexes:
            try:
                conn.execute(text(idx_sql))
                logger.info(f"✓ Index created")
            except ProgrammingError as e:
                if "already exists" in str(e):
                    logger.debug("Index already exists")
                else:
                    logger.warning(f"Could not create index: {e}")


def seed_initial_data():
    """
    Seed initial data for development/testing.
    
    This creates:
    - A default consent version configuration
    - An admin user (for testing)
    
    Skip in production by setting SKIP_SEED=true
    """
    if os.getenv("SKIP_SEED", "false").lower() == "true":
        logger.info("Skipping seed data (SKIP_SEED=true)")
        return
    
    logger.info("Seeding initial data...")
    
    session = SessionLocal()
    try:
        # Check if admin user already exists
        existing_admin = session.query(User).filter_by(username="admin").first()
        
        if not existing_admin:
            # Create admin user
            admin_user = User(
                username="admin",
                password_hash=None,  # Set password hash separately
                consent_version=1,
                is_active=True
            )
            session.add(admin_user)
            
            # Create initial audit log entry
            system_log = AuditLog(
                user_id=None,  # System event
                action=AuditAction.KEY_ROTATION,
                metadata_encrypted=None,
                success=True,
                error_message=None,
                session_id="INIT"
            )
            session.add(system_log)
            
            session.commit()
            logger.info("✓ Admin user created")
            logger.info("✓ Initial audit log entry created")
        else:
            logger.info("Admin user already exists, skipping seed")
            
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to seed data: {e}")
    finally:
        session.close()


def verify_setup():
    """Verify that all components are properly set up."""
    logger.info("Verifying database setup...")
    
    session = SessionLocal()
    try:
        # Test basic query
        user_count = session.query(User).count()
        logger.info(f"✓ Users table accessible ({user_count} records)")
        
        template_count = session.query(BiometricTemplate).count()
        logger.info(f"✓ BiometricTemplates table accessible ({template_count} records)")
        
        consent_count = session.query(ConsentRecord).count()
        logger.info(f"✓ ConsentRecords table accessible ({consent_count} records)")
        
        audit_count = session.query(AuditLog).count()
        logger.info(f"✓ AuditLogs table accessible ({audit_count} records)")
        
        # Test pgcrypto extension
        with engine.connect() as conn:
            result = conn.execute(text("SELECT gen_random_uuid()"))
            logger.info("✓ pgcrypto gen_random_uuid() working")
        
        logger.info("=" * 50)
        logger.info("Database setup verification PASSED")
        logger.info("=" * 50)
        
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        raise
    finally:
        session.close()


def init_database(drop_existing: bool = False):
    """
    Main initialization function.
    
    Args:
        drop_existing: If True, drop all tables before creating.
                      USE WITH EXTREME CAUTION IN PRODUCTION!
    """
    logger.info("=" * 50)
    logger.info("Starting database initialization...")
    logger.info("=" * 50)
    
    if drop_existing:
        if os.getenv("FLASK_ENV") == "production":
            raise ValueError(
                "Cannot drop tables in production! "
                "Set FLASK_ENV to 'development' or 'testing' to drop tables."
            )
        logger.warning("⚠️  Dropping all existing tables...")
        Base.metadata.drop_all(bind=engine)
        logger.info("All tables dropped")
    
    # Step 1: Create extensions
    create_extension()
    
    # Step 2: Create ENUM types
    create_enum_types()
    
    # Step 3: Create helper functions
    create_update_timestamp_function()
    create_audit_log_immutability_trigger()
    
    # Step 4: Create tables
    create_tables()
    
    # Step 5: Apply triggers (after tables exist)
    apply_audit_trigger()
    create_updated_at_triggers()
    
    # Step 6: Create performance indexes
    create_performance_indexes()
    
    # Step 7: Seed initial data
    seed_initial_data()
    
    # Step 8: Verify setup
    verify_setup()
    
    logger.info("=" * 50)
    logger.info("Database initialization COMPLETE")
    logger.info("=" * 50)


if __name__ == "__main__":
    # Check for --drop flag
    drop_flag = "--drop" in sys.argv
    
    if drop_flag:
        confirm = input(
            "⚠️  WARNING: This will DROP ALL TABLES. "
            "Type 'yes' to confirm: "
        )
        if confirm.lower() != "yes":
            print("Aborted.")
            sys.exit(1)
    
    init_database(drop_existing=drop_flag)
