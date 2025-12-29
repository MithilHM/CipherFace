"""
Database Models for Privacy-Preserving Facial Recognition System

This module defines SQLAlchemy ORM models with:
- UUID primary keys for distributed system compatibility
- Automatic timestamp management
- pgcrypto column-level encryption for sensitive fields
- DPDP Act 2023 compliant consent and audit logging

Security Model:
- Biometric templates stored as encrypted binary blobs (CKKS ciphertext)
- IP addresses encrypted at rest using PGPEncryptedType
- Audit logs are append-only (immutable) with encrypted metadata
- Soft deletion for all user-facing data (is_active flag)

Entity Relationships:
- User 1:N BiometricTemplate (one user can have multiple enrolled templates)
- User 1:N ConsentRecord (separate consent per purpose)
- User 1:N AuditLog (complete audit trail)
"""

import enum
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    create_engine,
    event,
    func,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

from .encryption_utils import EncryptedJSONType, PGPEncryptedType


# Database connection configuration
def get_database_url() -> str:
    """Build database URL from environment variables."""
    user = os.getenv("DB_USER", "postgres")
    password = os.getenv("DB_PASSWORD", "password")
    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "5432")
    name = os.getenv("DB_NAME", "face_db")
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


# SQLAlchemy 2.0 style declarative base
class Base(DeclarativeBase):
    """Base class for all models with common configurations."""
    pass


# ENUM Types for PostgreSQL
def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure a datetime object is timezone-aware (UTC)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class ConsentPurpose(enum.Enum):
    """
    Purpose enumeration for consent records.
    
    DPDP Act 2023 requires purpose limitation - data can only be used
    for the specific purpose for which consent was given.
    
    AUTHENTICATION: Consent to use biometric data for identity verification
    ACCESS_CONTROL: Consent to use biometric data for access control systems
    AUDIT: Consent to log authentication attempts for security auditing
    """
    AUTHENTICATION = "AUTHENTICATION"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    AUDIT = "AUDIT"


class AuditAction(enum.Enum):
    """
    Action types for audit logging.
    
    Comprehensive audit trail for DPDP compliance and breach investigation.
    """
    ENROLL = "ENROLL"                           # New biometric template registered
    AUTHENTICATE_SUCCESS = "AUTHENTICATE_SUCCESS"  # Successful authentication
    AUTHENTICATE_FAIL = "AUTHENTICATE_FAIL"     # Failed authentication attempt
    CONSENT_GRANT = "CONSENT_GRANT"             # User granted consent
    CONSENT_REVOKE = "CONSENT_REVOKE"           # User revoked consent
    DATA_DELETE = "DATA_DELETE"                 # User requested data deletion
    DATA_EXPORT = "DATA_EXPORT"                 # User exported their data
    SESSION_INVALIDATE = "SESSION_INVALIDATE"   # Sessions invalidated
    KEY_ROTATION = "KEY_ROTATION"               # Encryption key rotation event


class User(Base):
    """
    User model representing an individual in the system.
    
    Design Decisions:
    - UUID primary key: Enables distributed deployments, prevents ID guessing
    - username: Unique identifier, not the primary key (can be changed)
    - consent_version: Tracks which version of consent text user agreed to
    - is_active: Soft deletion flag for GDPR/DPDP right to erasure
    
    DPDP Compliance:
    - Minimal data collection (only essential fields)
    - Soft deletion preserves audit trail while removing active data
    """
    __tablename__ = "users"
    
    # Primary key: UUID for distributed compatibility
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
        comment="Unique identifier for the user"
    )
    
    # Username: unique identifier, indexed for fast lookups
    username: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique username for authentication"
    )
    
    # Password hash (for future JWT authentication)
    password_hash: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Bcrypt hashed password"
    )
    
    # Timestamps with timezone awareness
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Account creation timestamp"
    )
    
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        onupdate=func.now(),
        comment="Last profile update timestamp"
    )
    
    last_authentication: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        comment="Last successful authentication timestamp"
    )
    
    # Consent version tracking
    consent_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
        comment="Version of consent text user agreed to"
    )
    
    # Soft deletion flag
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
        comment="False if user data has been soft-deleted"
    )
    
    # Relationships with cascade delete
    biometric_templates: Mapped[list["BiometricTemplate"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin"  # Eager load to prevent N+1 queries
    )
    
    consent_records: Mapped[list["ConsentRecord"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="user",
        lazy="dynamic"  # Lazy load for large audit histories
    )
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, username={self.username}, active={self.is_active})>"
    
    def soft_delete(self) -> None:
        """Mark user as inactive (soft deletion)."""
        self.is_active = False
        # Also deactivate related templates
        for template in self.biometric_templates:
            template.is_active = False


class BiometricTemplate(Base):
    """
    Encrypted biometric template storage.
    
    Stores CKKS-encrypted face embeddings (~16KB binary blobs).
    The encryption happens at the application layer using homomorphic
    encryption, NOT pgcrypto (which is for metadata only).
    
    Design Decisions:
    - encrypted_embedding: LargeBinary for raw CKKS ciphertext storage
    - encryption_params_hash: Prevents mixing incompatible ciphertexts
    - Composite index on (user_id, is_active) for efficient queries
    
    Security:
    - Plaintext embeddings NEVER stored
    - encryption_params_hash enables key rotation tracking
    """
    __tablename__ = "biometric_templates"
    
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4
    )
    
    # Foreign key to user with cascade delete
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # CKKS encrypted embedding (~16KB binary blob)
    encrypted_embedding: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
        comment="CKKS homomorphically encrypted 512D face embedding"
    )
    
    # Hash of encryption parameters for compatibility checking
    encryption_params_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA-256 hash of CKKS parameters used for encryption"
    )
    
    # Template metadata
    template_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
        comment="Version number for re-enrollment tracking"
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        onupdate=func.now()
    )
    
    # Soft deletion
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False
    )
    
    # Relationship
    user: Mapped["User"] = relationship(back_populates="biometric_templates")
    
    # Composite index for efficient "get active templates for user" queries
    __table_args__ = (
        Index("ix_biometric_templates_user_active", "user_id", "is_active"),
    )
    
    def __repr__(self) -> str:
        size = len(self.encrypted_embedding) if self.encrypted_embedding else 0
        return f"<BiometricTemplate(id={self.id}, user_id={self.user_id}, size={size}B)>"


class ConsentRecord(Base):
    """
    Consent record for DPDP Act 2023 compliance.
    
    Each consent is purpose-specific (granular consent requirement).
    Consent text hash enables non-repudiation and tamper detection.
    
    DPDP Compliance:
    - Section 6: Explicit, informed consent with clear purpose
    - Section 11: Right to withdraw consent at any time
    - Purpose limitation: One record per purpose
    - IP address pseudonymized (encrypted)
    
    Design Decisions:
    - consent_text_hash: SHA-256 of text shown to user
    - ip_address_encrypted: Encrypted for pseudonymization
    - expires_at: Consent validity period (max 1 year recommended)
    """
    __tablename__ = "consent_records"
    
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4
    )
    
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Purpose of consent (DPDP purpose limitation)
    purpose: Mapped[ConsentPurpose] = mapped_column(
        Enum(ConsentPurpose, name="consent_purpose"),
        nullable=False
    )
    
    # Consent text integrity
    consent_text_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA-256 hash of consent text for tamper detection"
    )
    
    # Encrypted IP address (pseudonymization)
    ip_address_encrypted: Mapped[Optional[bytes]] = mapped_column(
        PGPEncryptedType(),
        comment="AES-256 encrypted IP address"
    )
    
    # Consent lifecycle timestamps
    consent_granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    
    consent_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Consent expiration (max 365 days from grant)"
    )
    
    # Revocation tracking
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )
    
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        comment="When consent was revoked"
    )
    
    revocation_reason: Mapped[Optional[str]] = mapped_column(
        Text,
        comment="Optional reason for consent revocation"
    )
    
    # Relationship
    user: Mapped["User"] = relationship(back_populates="consent_records")
    
    __table_args__ = (
        # Unique active consent per purpose per user (Partial Index)
        Index(
            "uq_consent_user_purpose_active",
            "user_id", "purpose",
            unique=True,
            postgresql_where="is_revoked = false"
        ),
        # Composite index for consent verification
        Index("ix_consent_verification", "user_id", "purpose", "is_revoked"),
        # Check constraint: revoked records must have revoked_at
        CheckConstraint(
            "(is_revoked = false) OR (revoked_at IS NOT NULL)",
            name="ck_consent_revoked_timestamp"
        ),
    )
    
    def __repr__(self) -> str:
        status = "REVOKED" if self.is_revoked else "ACTIVE"
        return f"<ConsentRecord(id={self.id}, purpose={self.purpose.value}, status={status})>"
    
    @property
    def is_expired(self) -> bool:
        """Check if consent has expired."""
        expires_at = ensure_utc(self.consent_expires_at)
        return datetime.now(timezone.utc) > expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if consent is valid (not revoked and not expired)."""
        return not self.is_revoked and not self.is_expired
    
    @property
    def remaining_days(self) -> int:
        """Calculate remaining days until expiration."""
        if self.is_expired:
            return 0
        expires_at = ensure_utc(self.consent_expires_at)
        delta = expires_at - datetime.now(timezone.utc)
        return max(0, delta.days)


class AuditLog(Base):
    """
    Immutable audit log for security and compliance.
    
    DPDP Compliance:
    - Complete audit trail of all biometric operations
    - Encrypted metadata (IP addresses, user agents)
    - Immutable: No UPDATE operations allowed (enforced by trigger)
    - 7-year retention period for compliance
    
    Security:
    - Append-only design prevents tampering
    - Database trigger blocks UPDATE statements
    - Encrypted metadata protects sensitive details
    
    Breach Notification:
    - Enables querying affected users within 1 hour
    - Timestamp indexing for efficient date range queries
    """
    __tablename__ = "audit_logs"
    
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4
    )
    
    # User reference (nullable for system-level events)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid,
        ForeignKey("users.id", ondelete="SET NULL"),  # Preserve logs on user delete
        index=True
    )
    
    # Action type
    action: Mapped[AuditAction] = mapped_column(
        Enum(AuditAction, name="audit_action"),
        nullable=False,
        index=True
    )
    
    # Encrypted metadata (IP, user agent, etc.)
    metadata_encrypted: Mapped[Optional[bytes]] = mapped_column(
        EncryptedJSONType(),
        comment="AES-256 encrypted JSON metadata"
    )
    
    # Timestamp (indexed for range queries)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    
    # Operation result
    success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True
    )
    
    # Error message for failed operations
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        comment="Error details for failed operations"
    )
    
    # Session ID for correlation
    session_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        comment="Session identifier for correlating related events"
    )
    
    # Relationship
    user: Mapped[Optional["User"]] = relationship(back_populates="audit_logs")
    
    __table_args__ = (
        # Composite index for user activity queries
        Index("ix_audit_user_timestamp", "user_id", "timestamp"),
        # Index for action-based queries (breach investigation)
        Index("ix_audit_action_timestamp", "action", "timestamp"),
    )
    
    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action.value}, success={self.success})>"


# Prevent UPDATE operations on audit_logs
@event.listens_for(AuditLog, "before_update")
def prevent_audit_log_update(mapper, connection, target):
    """
    Raise exception if someone tries to update an audit log.
    
    This is a Python-level safeguard. Database trigger provides
    additional protection at the SQL level.
    """
    raise ValueError(
        "AuditLog records are immutable. UPDATE operations are not allowed. "
        "This is required for DPDP Act compliance and audit trail integrity."
    )


# Engine and session factory
engine = create_engine(
    get_database_url(),
    pool_size=20,          # Connection pool size
    max_overflow=30,       # Extra connections allowed
    pool_timeout=30,       # Wait timeout for connection
    pool_recycle=1800,     # Recycle connections after 30 min
    echo=os.getenv("SQL_DEBUG", "false").lower() == "true"
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """
    Database session dependency for Flask/FastAPI.
    
    Usage:
        @app.route("/api/users")
        def get_users():
            db = next(get_db())
            try:
                users = db.query(User).all()
                return users
            finally:
                db.close()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create all database tables."""
    Base.metadata.create_all(bind=engine)


def drop_tables():
    """Drop all database tables (use with caution!)."""
    Base.metadata.drop_all(bind=engine)
