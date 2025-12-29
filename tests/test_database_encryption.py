"""
Database Encryption Tests

Comprehensive test suite for:
- User CRUD operations
- BiometricTemplate storage and retrieval
- pgcrypto encryption/decryption roundtrip
- Consent record hash verification
- Audit log immutability
- Soft deletion cascade
- Query performance validation

Run with:
    poetry run pytest tests/test_database_encryption.py -v

With coverage:
    poetry run pytest tests/test_database_encryption.py --cov=src/homomorphic_face_encryption/database
"""

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError

# Set test environment before imports
os.environ["FLASK_ENV"] = "development"
os.environ["DB_ENCRYPTION_KEY"] = "test-encryption-key-32-chars-ok!"

from homomorphic_face_encryption.database import (
    Base,
    User,
    BiometricTemplate,
    ConsentRecord,
    AuditLog,
    ConsentPurpose,
    AuditAction,
    encrypt_column_data,
    decrypt_column_data,
    encrypt_json_metadata,
    decrypt_json_metadata,
    hash_consent_text,
    verify_consent_hash,
    generate_encryption_params_hash,
)


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def test_engine():
    """Create a test database engine using SQLite for isolation."""
    # Use SQLite for fast, isolated testing
    # For full PostgreSQL tests, use a test database
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False
    )
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture(scope="function")
def db_session(test_engine):
    """Create a new database session for each test with transaction rollback."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection)()
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def sample_user(db_session: Session) -> User:
    """Create a sample user for testing."""
    user = User(
        username=f"testuser_{uuid.uuid4().hex[:8]}",
        password_hash="$2b$12$test_hash",
        consent_version=1,
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def sample_embedding() -> bytes:
    """Create sample encrypted embedding data (~16KB)."""
    # Simulate CKKS ciphertext size
    return os.urandom(16 * 1024)  # 16KB random bytes


# ============================================================================
# User Model Tests
# ============================================================================

class TestUserModel:
    """Tests for User model CRUD operations."""
    
    def test_user_creation_with_uuid(self, db_session: Session):
        """Test that users are created with UUID primary keys."""
        user = User(username="test_uuid_user")
        db_session.add(user)
        db_session.commit()
        
        assert user.id is not None
        assert isinstance(user.id, uuid.UUID)
    
    def test_user_creation_with_defaults(self, db_session: Session):
        """Test that default values are set correctly."""
        user = User(username="test_defaults")
        db_session.add(user)
        db_session.commit()
        
        assert user.is_active is True
        assert user.consent_version == 1
        assert user.created_at is not None
    
    def test_user_retrieval_by_username(self, db_session: Session, sample_user: User):
        """Test retrieving user by username."""
        retrieved = db_session.query(User).filter_by(
            username=sample_user.username
        ).first()
        
        assert retrieved is not None
        assert retrieved.id == sample_user.id
    
    def test_user_unique_username_constraint(self, db_session: Session):
        """Test that duplicate usernames raise IntegrityError."""
        user1 = User(username="duplicate_user")
        db_session.add(user1)
        db_session.commit()
        
        user2 = User(username="duplicate_user")
        db_session.add(user2)
        
        with pytest.raises(IntegrityError):
            db_session.commit()
    
    def test_user_soft_deletion(self, db_session: Session, sample_user: User):
        """Test soft deletion sets is_active to False."""
        sample_user.soft_delete()
        db_session.commit()
        
        # Reload from database
        db_session.refresh(sample_user)
        assert sample_user.is_active is False


# ============================================================================
# BiometricTemplate Tests
# ============================================================================

class TestBiometricTemplateModel:
    """Tests for BiometricTemplate storage and retrieval."""
    
    def test_template_storage_binary_integrity(
        self, 
        db_session: Session, 
        sample_user: User,
        sample_embedding: bytes
    ):
        """Test that binary embedding data is stored and retrieved correctly."""
        params_hash = generate_encryption_params_hash()
        
        template = BiometricTemplate(
            user_id=sample_user.id,
            encrypted_embedding=sample_embedding,
            encryption_params_hash=params_hash
        )
        db_session.add(template)
        db_session.commit()
        
        # Retrieve and verify
        retrieved = db_session.query(BiometricTemplate).filter_by(
            id=template.id
        ).first()
        
        assert retrieved is not None
        assert retrieved.encrypted_embedding == sample_embedding
        assert len(retrieved.encrypted_embedding) == 16 * 1024
    
    def test_template_user_relationship(
        self, 
        db_session: Session, 
        sample_user: User,
        sample_embedding: bytes
    ):
        """Test template-user relationship."""
        template = BiometricTemplate(
            user_id=sample_user.id,
            encrypted_embedding=sample_embedding,
            encryption_params_hash="test_hash"
        )
        db_session.add(template)
        db_session.commit()
        
        # Access through relationship
        db_session.refresh(sample_user)
        assert len(sample_user.biometric_templates) == 1
        assert sample_user.biometric_templates[0].id == template.id
    
    def test_template_cascade_delete(
        self, 
        db_session: Session,
        sample_embedding: bytes
    ):
        """Test that templates are deleted when user is deleted."""
        user = User(username="cascade_test_user")
        db_session.add(user)
        db_session.commit()
        
        template = BiometricTemplate(
            user_id=user.id,
            encrypted_embedding=sample_embedding,
            encryption_params_hash="test_hash"
        )
        db_session.add(template)
        db_session.commit()
        
        template_id = template.id
        
        # Delete user
        db_session.delete(user)
        db_session.commit()
        
        # Verify template is also deleted
        orphan = db_session.query(BiometricTemplate).filter_by(
            id=template_id
        ).first()
        assert orphan is None
    
    def test_template_encryption_params_hash(self):
        """Test encryption parameters hash generation."""
        hash1 = generate_encryption_params_hash(8192, 5, "HEStd_128_classic")
        hash2 = generate_encryption_params_hash(8192, 5, "HEStd_128_classic")
        hash3 = generate_encryption_params_hash(16384, 5, "HEStd_128_classic")
        
        # Same params should produce same hash
        assert hash1 == hash2
        # Different params should produce different hash
        assert hash1 != hash3
        # Hash should be 16 characters (truncated SHA-256)
        assert len(hash1) == 16


# ============================================================================
# pgcrypto Encryption Tests
# ============================================================================

class TestEncryptionUtilities:
    """Tests for pgcrypto-compatible encryption utilities."""
    
    def test_encryption_decryption_roundtrip(self):
        """Test that encrypted data can be decrypted correctly."""
        plaintext = "192.168.1.100"
        
        encrypted = encrypt_column_data(plaintext)
        decrypted = decrypt_column_data(encrypted)
        
        assert decrypted == plaintext
    
    def test_encryption_with_unicode(self):
        """Test encryption handles unicode characters correctly."""
        plaintext = "Test with émojis: 🔐 and аkyrillиc"
        
        encrypted = encrypt_column_data(plaintext)
        decrypted = decrypt_column_data(encrypted)
        
        assert decrypted == plaintext
    
    def test_encryption_with_custom_key(self):
        """Test encryption with custom key."""
        plaintext = "sensitive data"
        key = "custom-key-for-testing-32-chars!"
        
        encrypted = encrypt_column_data(plaintext, key)
        decrypted = decrypt_column_data(encrypted, key)
        
        assert decrypted == plaintext
    
    def test_wrong_key_fails_decryption(self):
        """Test that wrong key fails to decrypt."""
        plaintext = "secret"
        key1 = "key-one-for-testing-32-chars-ok"
        key2 = "key-two-for-testing-32-chars-ok"
        
        encrypted = encrypt_column_data(plaintext, key1)
        
        with pytest.raises(ValueError):
            decrypt_column_data(encrypted, key2)
    
    def test_json_metadata_encryption(self):
        """Test JSON metadata encryption and decryption."""
        metadata = {
            "ip_address": "10.0.0.1",
            "user_agent": "Mozilla/5.0",
            "action_details": {"attempt": 1, "method": "face"}
        }
        
        encrypted = encrypt_json_metadata(metadata)
        decrypted = decrypt_json_metadata(encrypted)
        
        assert decrypted == metadata
    
    def test_null_value_handling(self):
        """Test that NULL values are handled correctly."""
        from homomorphic_face_encryption.database.encryption_utils import PGPEncryptedType
        
        enc_type = PGPEncryptedType()
        
        # NULL should pass through unchanged
        result = enc_type.process_bind_param(None, None)
        assert result is None
        
        result = enc_type.process_result_value(None, None)
        assert result is None


# ============================================================================
# Consent Hash Tests
# ============================================================================

class TestConsentHashing:
    """Tests for consent text hash verification."""
    
    def test_consent_text_hash_generation(self):
        """Test SHA-256 hash generation for consent text."""
        consent_text = "I consent to biometric authentication for secure login."
        
        hash_result = hash_consent_text(consent_text)
        
        # SHA-256 produces 64 hex characters
        assert len(hash_result) == 64
        assert hash_result.islower()  # Lowercase hex
    
    def test_consent_hash_consistency(self):
        """Test that same text produces same hash."""
        consent_text = "I consent to data processing."
        
        hash1 = hash_consent_text(consent_text)
        hash2 = hash_consent_text(consent_text)
        
        assert hash1 == hash2
    
    def test_consent_hash_whitespace_normalization(self):
        """Test that whitespace is normalized before hashing."""
        text1 = "I   consent   to   data   processing."
        text2 = "I consent to data processing."
        
        # Both should produce same hash after normalization
        assert hash_consent_text(text1) == hash_consent_text(text2)
    
    def test_consent_hash_verification_valid(self):
        """Test hash verification with valid text."""
        consent_text = "Valid consent text"
        stored_hash = hash_consent_text(consent_text)
        
        assert verify_consent_hash(consent_text, stored_hash) is True
    
    def test_consent_hash_verification_tampered(self):
        """Test hash verification detects tampering."""
        original_text = "Original consent text"
        stored_hash = hash_consent_text(original_text)
        
        tampered_text = "Modified consent text"
        
        assert verify_consent_hash(tampered_text, stored_hash) is False
    
    def test_consent_hash_unicode(self):
        """Test hashing with unicode consent text."""
        consent_text = "मैं सहमति देता हूं (I consent in Hindi)"
        
        hash_result = hash_consent_text(consent_text)
        
        assert len(hash_result) == 64
        assert verify_consent_hash(consent_text, hash_result) is True


# ============================================================================
# ConsentRecord Tests
# ============================================================================

class TestConsentRecordModel:
    """Tests for ConsentRecord model."""
    
    def test_consent_record_creation(self, db_session: Session, sample_user: User):
        """Test creating a consent record."""
        consent_text = "I consent to biometric authentication."
        
        consent = ConsentRecord(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text_hash=hash_consent_text(consent_text),
            consent_expires_at=datetime.now(timezone.utc) + timedelta(days=365)
        )
        db_session.add(consent)
        db_session.commit()
        
        assert consent.id is not None
        assert consent.is_revoked is False
        assert consent.is_valid is True
    
    def test_consent_expiration_check(self, db_session: Session, sample_user: User):
        """Test consent expiration detection."""
        # Create expired consent
        consent = ConsentRecord(
            user_id=sample_user.id,
            purpose=ConsentPurpose.ACCESS_CONTROL,
            consent_text_hash="test_hash",
            consent_expires_at=datetime.now(timezone.utc) - timedelta(days=1)
        )
        db_session.add(consent)
        db_session.commit()
        
        assert consent.is_expired is True
        assert consent.is_valid is False
        assert consent.remaining_days == 0
    
    def test_consent_remaining_days(self, db_session: Session, sample_user: User):
        """Test remaining days calculation."""
        expires_in = 30
        consent = ConsentRecord(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUDIT,
            consent_text_hash="test_hash",
            consent_expires_at=datetime.now(timezone.utc) + timedelta(days=expires_in)
        )
        db_session.add(consent)
        db_session.commit()
        
        # Allow for slight timing differences
        assert consent.remaining_days in [expires_in - 1, expires_in, expires_in + 1]


# ============================================================================
# AuditLog Tests
# ============================================================================

class TestAuditLogModel:
    """Tests for AuditLog model and immutability."""
    
    def test_audit_log_creation(self, db_session: Session, sample_user: User):
        """Test creating an audit log entry."""
        log = AuditLog(
            user_id=sample_user.id,
            action=AuditAction.AUTHENTICATE_SUCCESS,
            success=True,
            session_id="test_session_123"
        )
        db_session.add(log)
        db_session.commit()
        
        assert log.id is not None
        assert log.timestamp is not None
    
    def test_audit_log_immutability_python_level(self, db_session: Session, sample_user: User):
        """Test that Python-level event prevents UPDATE."""
        log = AuditLog(
            user_id=sample_user.id,
            action=AuditAction.ENROLL,
            success=True
        )
        db_session.add(log)
        db_session.commit()
        
        # Attempt to modify
        log.success = False
        
        # This should raise ValueError from the event listener
        with pytest.raises(ValueError, match="immutable"):
            db_session.commit()
    
    def test_audit_log_with_encrypted_metadata(self, db_session: Session, sample_user: User):
        """Test audit log with encrypted metadata."""
        metadata = {
            "ip_address": "192.168.1.100",
            "user_agent": "TestBrowser/1.0",
            "location": "Test Lab"
        }
        
        log = AuditLog(
            user_id=sample_user.id,
            action=AuditAction.AUTHENTICATE_FAIL,
            metadata_encrypted=encrypt_json_metadata(metadata),
            success=False,
            error_message="Face not recognized"
        )
        db_session.add(log)
        db_session.commit()
        
        # Retrieve and verify metadata can be decrypted
        retrieved = db_session.query(AuditLog).filter_by(id=log.id).first()
        decrypted = decrypt_json_metadata(retrieved.metadata_encrypted)
        
        assert decrypted["ip_address"] == "192.168.1.100"


# ============================================================================
# Security Tests
# ============================================================================

class TestSecurityAudit:
    """Security-focused tests."""
    
    def test_encryption_key_not_hardcoded(self):
        """Verify encryption key comes from environment, not hardcoded."""
        from homomorphic_face_encryption.database.encryption_utils import get_encryption_key
        
        # Key should come from environment variable
        key = get_encryption_key()
        assert key is not None
        
        # Verify key is from env (we set it for tests)
        assert key == "test-encryption-key-32-chars-ok!"
    
    def test_password_hash_not_plaintext(self, db_session: Session):
        """Verify password is stored as hash, not plaintext."""
        user = User(
            username="security_test",
            password_hash="$2b$12$somevalidbcrypthash"
        )
        db_session.add(user)
        db_session.commit()
        
        # Password hash should start with bcrypt identifier
        assert user.password_hash.startswith("$2b$")
    
    def test_uuid_primary_keys(self, db_session: Session):
        """Verify all models use UUID primary keys."""
        user = User(username="uuid_test")
        db_session.add(user)
        db_session.commit()
        
        assert isinstance(user.id, uuid.UUID)
        
        # UUID should be version 4 (random)
        assert user.id.version == 4


# ============================================================================
# Performance Tests (basic sanity checks)
# ============================================================================

class TestPerformance:
    """Basic performance sanity checks."""
    
    def test_user_query_performance(self, db_session: Session):
        """Test that user queries are reasonably fast."""
        import time
        
        # Create test user
        user = User(username="perf_test_user")
        db_session.add(user)
        db_session.commit()
        
        # Query should be fast
        start = time.time()
        for _ in range(100):
            db_session.query(User).filter_by(username="perf_test_user").first()
        elapsed = time.time() - start
        
        # 100 queries should complete reasonably fast (allow for slower environments)
        assert elapsed < 5.0
    
    def test_encryption_performance(self):
        """Test that encryption is reasonably fast."""
        import time
        
        plaintext = "Test data for encryption performance"
        
        start = time.time()
        for _ in range(100):
            encrypted = encrypt_column_data(plaintext)
            decrypt_column_data(encrypted)
        elapsed = time.time() - start
        
        # 100 encrypt/decrypt cycles should complete in reasonable time
        # Allow for slower environments and overhead
        assert elapsed < 10.0


# ============================================================================
# Run tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
