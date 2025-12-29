"""
Database module for Privacy-Preserving Facial Recognition System.

This module provides:
- SQLAlchemy ORM models (User, BiometricTemplate, ConsentRecord, AuditLog)
- pgcrypto encryption utilities for column-level encryption
- Database initialization and migration tools

Usage:
    from homomorphic_face_encryption.database import (
        User,
        BiometricTemplate,
        ConsentRecord,
        AuditLog,
        ConsentPurpose,
        AuditAction,
        get_db,
        SessionLocal,
        engine,
    )
    
    # Get database session
    db = next(get_db())
    
    # Query users
    users = db.query(User).filter_by(is_active=True).all()
"""

from .models import (
    # Base class
    Base,
    
    # Models
    User,
    BiometricTemplate,
    ConsentRecord,
    AuditLog,
    
    # Enums
    ConsentPurpose,
    AuditAction,
    
    # Database utilities
    engine,
    SessionLocal,
    get_db,
    create_tables,
    drop_tables,
    get_database_url,
)

from .encryption_utils import (
    # Encryption functions
    encrypt_column_data,
    decrypt_column_data,
    encrypt_json_metadata,
    decrypt_json_metadata,
    hash_consent_text,
    verify_consent_hash,
    
    # SQLAlchemy custom types
    PGPEncryptedType,
    EncryptedJSONType,
    
    # Setup functions
    setup_pgcrypto,
    get_encryption_key,
    generate_encryption_params_hash,
)

__all__ = [
    # Base
    "Base",
    
    # Models
    "User",
    "BiometricTemplate", 
    "ConsentRecord",
    "AuditLog",
    
    # Enums
    "ConsentPurpose",
    "AuditAction",
    
    # Database utilities
    "engine",
    "SessionLocal",
    "get_db",
    "create_tables",
    "drop_tables",
    "get_database_url",
    
    # Encryption functions
    "encrypt_column_data",
    "decrypt_column_data",
    "encrypt_json_metadata",
    "decrypt_json_metadata",
    "hash_consent_text",
    "verify_consent_hash",
    
    # SQLAlchemy custom types
    "PGPEncryptedType",
    "EncryptedJSONType",
    
    # Setup functions
    "setup_pgcrypto",
    "get_encryption_key",
    "generate_encryption_params_hash",
]
