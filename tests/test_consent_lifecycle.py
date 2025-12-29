"""
Consent Lifecycle Tests

Integration tests for the DPDP-compliant consent management system:
- Consent grant/verify/revoke flow
- Cache behavior and invalidation
- Middleware blocking without consent
- Session invalidation on revoke
- Data export and deletion
- DPDP compliance verification

Run with:
    poetry run pytest tests/test_consent_lifecycle.py -v

With coverage:
    poetry run pytest tests/test_consent_lifecycle.py --cov=src/homomorphic_face_encryption/consent
"""

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token

# Set test environment before imports
os.environ["FLASK_ENV"] = "development"
os.environ["DB_ENCRYPTION_KEY"] = "test-encryption-key-32-chars-ok!"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from homomorphic_face_encryption.database import (
    Base,
    User,
    BiometricTemplate,
    ConsentRecord,
    AuditLog,
    ConsentPurpose,
    AuditAction,
    hash_consent_text,
    encrypt_json_metadata,
    generate_encryption_params_hash,
)
from homomorphic_face_encryption.consent.consent_service import (
    ConsentService,
    ConsentVerificationResult,
    ConsentGrantResult,
)
from homomorphic_face_encryption.consent.manager import (
    ConsentManager,
    CONSENT_TEXT_AUTHENTICATION,
)


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def test_engine():
    """Create test database engine."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture(scope="function")
def db_session(test_engine):
    """Create database session with transaction rollback."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection)()
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def mock_redis():
    """Create mock Redis client."""
    redis = MagicMock()
    redis.get.return_value = None
    redis.setex.return_value = True
    redis.delete.return_value = True
    redis.scan_iter.return_value = iter([])
    redis.publish.return_value = True
    return redis


@pytest.fixture
def consent_service(db_session, mock_redis):
    """Create consent service with mocked Redis."""
    return ConsentService(db_session, mock_redis)


@pytest.fixture
def sample_user(db_session) -> User:
    """Create sample user."""
    user = User(
        username=f"testuser_{uuid.uuid4().hex[:8]}",
        consent_version=1,
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def valid_consent_text():
    """Valid consent text (>100 chars)."""
    return CONSENT_TEXT_AUTHENTICATION


@pytest.fixture
def app():
    """Create Flask test application."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test-secret'
    app.config['JWT_SECRET_KEY'] = 'jwt-test-secret'
    app.config['TESTING'] = True
    JWTManager(app)
    return app


# ============================================================================
# Consent Grant Tests
# ============================================================================

class TestConsentGrant:
    """Tests for consent grant functionality."""
    
    def test_grant_consent_creates_record(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str
    ):
        """Test that granting consent creates a database record."""
        result = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365,
            ip_address="192.168.1.1"
        )
        
        assert result.success is True
        assert result.consent_id is not None
        assert result.status == "active"
        assert result.expires_at is not None
    
    def test_grant_consent_requires_valid_text(
        self,
        consent_service: ConsentService,
        sample_user: User
    ):
        """Test that consent text must be at least 100 characters."""
        result = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text="Too short",
            expires_in_days=365
        )
        
        assert result.success is False
        assert result.status == "invalid_consent_text"
    
    def test_grant_consent_validates_expiration(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str
    ):
        """Test expiration must be 1-365 days."""
        # Too long
        result = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=500
        )
        assert result.success is False
        assert result.status == "invalid_expiration"
        
        # Zero days
        result = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=0
        )
        assert result.success is False
    
    def test_duplicate_consent_prevented(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str
    ):
        """Test that duplicate active consent for same purpose is prevented."""
        # First grant should succeed
        result1 = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        assert result1.success is True
        
        # Second grant for same purpose should fail
        result2 = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        assert result2.success is False
        assert result2.status == "duplicate_consent"
    
    def test_consent_for_different_purposes_allowed(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str
    ):
        """Test that consent for different purposes is allowed."""
        # Grant for AUTHENTICATION
        result1 = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        assert result1.success is True
        
        # Grant for ACCESS_CONTROL should also succeed
        result2 = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.ACCESS_CONTROL,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        assert result2.success is True
    
    def test_consent_hash_stored_correctly(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str,
        db_session
    ):
        """Test that consent text hash is stored correctly."""
        result = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # Retrieve consent record
        consent = db_session.query(ConsentRecord).filter_by(
            id=result.consent_id
        ).first()
        
        # Verify hash
        expected_hash = hash_consent_text(valid_consent_text)
        assert consent.consent_text_hash == expected_hash


# ============================================================================
# Consent Verification Tests
# ============================================================================

class TestConsentVerification:
    """Tests for consent verification functionality."""
    
    def test_verify_with_valid_consent(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str
    ):
        """Test verification with valid active consent."""
        # Grant consent first
        consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # Verify
        result = consent_service.verify_consent(
            sample_user.id,
            ConsentPurpose.AUTHENTICATION
        )
        
        assert result.valid is True
        assert result.status == "active"
        assert result.remaining_days > 0
    
    def test_verify_without_consent(
        self,
        consent_service: ConsentService,
        sample_user: User
    ):
        """Test verification when no consent exists."""
        result = consent_service.verify_consent(
            sample_user.id,
            ConsentPurpose.AUTHENTICATION
        )
        
        assert result.valid is False
        assert result.status == "not_found"
    
    def test_verify_expired_consent(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str,
        db_session
    ):
        """Test verification with expired consent."""
        # Create expired consent directly
        expired_consent = ConsentRecord(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text_hash=hash_consent_text(valid_consent_text),
            consent_granted_at=datetime.now(timezone.utc) - timedelta(days=400),
            consent_expires_at=datetime.now(timezone.utc) - timedelta(days=35),
            is_revoked=False
        )
        db_session.add(expired_consent)
        db_session.commit()
        
        # Verify should return expired
        result = consent_service.verify_consent(
            sample_user.id,
            ConsentPurpose.AUTHENTICATION
        )
        
        assert result.valid is False
        assert result.status == "expired"
    
    def test_verify_revoked_consent(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str
    ):
        """Test verification with revoked consent."""
        # Grant and revoke
        grant_result = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        consent_service.revoke_consent(
            consent_id=grant_result.consent_id,
            user_id=sample_user.id,
            reason="Test revocation"
        )
        
        # Verify should fail
        result = consent_service.verify_consent(
            sample_user.id,
            ConsentPurpose.AUTHENTICATION
        )
        
        assert result.valid is False
        # Status could be "not_found" since revoked consents aren't returned
    
    def test_verify_uses_cache(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str,
        mock_redis
    ):
        """Test that verification uses Redis cache."""
        # Grant consent
        consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # First verification should cache
        consent_service.verify_consent(
            sample_user.id,
            ConsentPurpose.AUTHENTICATION
        )
        
        # Verify cache was set
        assert mock_redis.setex.called


# ============================================================================
# Consent Revocation Tests
# ============================================================================

class TestConsentRevocation:
    """Tests for consent revocation functionality."""
    
    def test_revoke_consent_success(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str
    ):
        """Test successful consent revocation."""
        # Grant first
        grant = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # Revoke
        success = consent_service.revoke_consent(
            consent_id=grant.consent_id,
            user_id=sample_user.id,
            reason="User requested"
        )
        
        assert success is True
    
    def test_revoke_nonexistent_consent(
        self,
        consent_service: ConsentService,
        sample_user: User
    ):
        """Test revoking non-existent consent returns False."""
        success = consent_service.revoke_consent(
            consent_id=uuid.uuid4(),
            user_id=sample_user.id
        )
        
        assert success is False
    
    def test_revoke_invalidates_cache(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str,
        mock_redis
    ):
        """Test that revocation invalidates consent cache."""
        # Grant
        grant = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # Revoke
        consent_service.revoke_consent(
            consent_id=grant.consent_id,
            user_id=sample_user.id
        )
        
        # Verify cache delete was called
        assert mock_redis.delete.called
    
    def test_revoke_auth_consent_deactivates_templates(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str,
        db_session
    ):
        """Test that revoking AUTH consent soft-deletes biometric templates."""
        # Create biometric template
        template = BiometricTemplate(
            user_id=sample_user.id,
            encrypted_embedding=b"test_embedding" * 1000,
            encryption_params_hash="test_hash",
            is_active=True
        )
        db_session.add(template)
        db_session.commit()
        
        # Grant consent
        grant = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # Revoke
        consent_service.revoke_consent(
            consent_id=grant.consent_id,
            user_id=sample_user.id
        )
        
        # Verify template is deactivated
        db_session.refresh(template)
        assert template.is_active is False


# ============================================================================
# Consent Cache Tests
# ============================================================================

class TestConsentCache:
    """Tests for consent caching behavior."""
    
    def test_cache_key_generation(self, consent_service: ConsentService):
        """Test cache key format."""
        user_id = uuid.uuid4()
        key = consent_service._get_cache_key(user_id, ConsentPurpose.AUTHENTICATION)
        
        assert key == f"consent_cache:{user_id}:AUTHENTICATION"
    
    def test_cache_stores_verification_result(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str,
        mock_redis
    ):
        """Test that verification result is cached correctly."""
        # Grant consent
        consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # Verify to trigger caching
        consent_service.verify_consent(
            sample_user.id,
            ConsentPurpose.AUTHENTICATION
        )
        
        # Check setex was called with correct TTL
        call_args = mock_redis.setex.call_args
        assert call_args is not None
        assert call_args[0][1] == 60  # TTL should be 60 seconds
    
    def test_cache_hit_returns_cached_result(
        self,
        db_session,
        sample_user: User
    ):
        """Test that cache hit returns cached result without DB query."""
        cached_data = {
            "valid": True,
            "consent_id": str(uuid.uuid4()),
            "purpose": "AUTHENTICATION",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            "remaining_days": 30,
            "status": "active"
        }
        
        mock_redis = MagicMock()
        mock_redis.get.return_value = json.dumps(cached_data)
        
        service = ConsentService(db_session, mock_redis)
        
        result = service.verify_consent(
            sample_user.id,
            ConsentPurpose.AUTHENTICATION
        )
        
        assert result.valid is True
        assert result.cached is True


# ============================================================================
# Dashboard and Export Tests
# ============================================================================

class TestDashboardAndExport:
    """Tests for dashboard and data export functionality."""
    
    def test_get_dashboard_data(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str,
        db_session
    ):
        """Test dashboard data retrieval."""
        # Grant consent
        consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # Get dashboard
        data = consent_service.get_dashboard_data(sample_user.id)
        
        assert "user" in data
        assert "active_consents" in data
        assert "authentication_history" in data
        assert "data_summary" in data
        assert len(data["active_consents"]) == 1
    
    def test_export_user_data(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str
    ):
        """Test complete user data export."""
        # Grant consent
        consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # Export
        export = consent_service.export_user_data(sample_user.id)
        
        assert "export_date" in export
        assert "user" in export
        assert "consent_records" in export
        assert "audit_logs" in export
        assert export["user"]["username"] == sample_user.username
    
    def test_export_excludes_biometric_templates(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str,
        db_session
    ):
        """Test that biometric templates are not exported."""
        # Create template
        template = BiometricTemplate(
            user_id=sample_user.id,
            encrypted_embedding=b"secret_biometric_data" * 100,
            encryption_params_hash="test",
            is_active=True
        )
        db_session.add(template)
        db_session.commit()
        
        # Export
        export = consent_service.export_user_data(sample_user.id)
        
        # Templates should be counted but not included
        assert export["biometric_templates"]["count"] == 1
        assert "note" in export["biometric_templates"]


# ============================================================================
# Soft Delete Tests
# ============================================================================

class TestSoftDelete:
    """Tests for biometric data soft deletion."""
    
    def test_soft_delete_deactivates_templates(
        self,
        consent_service: ConsentService,
        sample_user: User,
        db_session
    ):
        """Test that soft delete deactivates all templates."""
        # Create templates
        for i in range(3):
            template = BiometricTemplate(
                user_id=sample_user.id,
                encrypted_embedding=b"data" * 1000,
                encryption_params_hash=f"hash_{i}",
                is_active=True
            )
            db_session.add(template)
        db_session.commit()
        
        # Soft delete
        count = consent_service.soft_delete_biometric_data(sample_user.id)
        
        assert count == 3
        
        # Verify all are inactive
        active = db_session.query(BiometricTemplate).filter_by(
            user_id=sample_user.id,
            is_active=True
        ).count()
        assert active == 0
    
    def test_soft_delete_revokes_all_consents(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str,
        db_session
    ):
        """Test that soft delete revokes all consents."""
        # Grant multiple consents
        consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.ACCESS_CONTROL,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # Soft delete
        consent_service.soft_delete_biometric_data(sample_user.id)
        
        # Verify all consents are revoked
        active_consents = db_session.query(ConsentRecord).filter_by(
            user_id=sample_user.id,
            is_revoked=False
        ).count()
        assert active_consents == 0
    
    def test_soft_delete_creates_audit_log(
        self,
        consent_service: ConsentService,
        sample_user: User,
        db_session
    ):
        """Test that soft delete creates audit log entry."""
        # Soft delete
        consent_service.soft_delete_biometric_data(sample_user.id)
        
        # Check audit log
        log = db_session.query(AuditLog).filter_by(
            user_id=sample_user.id,
            action=AuditAction.DATA_DELETE
        ).first()
        
        assert log is not None
        assert log.success is True


# ============================================================================
# Consent Manager Tests
# ============================================================================

class TestConsentManager:
    """Tests for ConsentManager high-level interface."""
    
    def test_has_valid_consent(
        self,
        db_session,
        sample_user: User,
        valid_consent_text: str
    ):
        """Test has_valid_consent convenience method."""
        manager = ConsentManager(db_session, None)
        
        # Initially no consent
        assert manager.has_valid_consent(
            sample_user.id,
            ConsentPurpose.AUTHENTICATION
        ) is False
        
        # Grant consent
        manager.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text
        )
        
        # Now should have consent
        assert manager.has_valid_consent(
            sample_user.id,
            ConsentPurpose.AUTHENTICATION
        ) is True
        
        manager.close()
    
    def test_context_manager_usage(self, db_session, sample_user: User):
        """Test using ConsentManager as context manager."""
        with ConsentManager(db_session, None) as manager:
            result = manager.verify_consent(
                sample_user.id,
                ConsentPurpose.AUTHENTICATION
            )
            assert result.valid is False


# ============================================================================
# DPDP Compliance Tests
# ============================================================================

class TestDPDPCompliance:
    """Tests verifying DPDP Act 2023 compliance requirements."""
    
    def test_purpose_limitation(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str
    ):
        """DPDP: Consent is purpose-specific (Section 6)."""
        # Grant only AUTHENTICATION consent
        consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # AUTHENTICATION should be valid
        auth_result = consent_service.verify_consent(
            sample_user.id,
            ConsentPurpose.AUTHENTICATION
        )
        assert auth_result.valid is True
        
        # ACCESS_CONTROL should NOT be valid
        access_result = consent_service.verify_consent(
            sample_user.id,
            ConsentPurpose.ACCESS_CONTROL
        )
        assert access_result.valid is False
    
    def test_right_to_withdraw(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str
    ):
        """DPDP: User can withdraw consent at any time (Section 11)."""
        # Grant consent
        grant = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # Withdraw (revoke)
        success = consent_service.revoke_consent(
            consent_id=grant.consent_id,
            user_id=sample_user.id
        )
        assert success is True
        
        # Verification should now fail
        result = consent_service.verify_consent(
            sample_user.id,
            ConsentPurpose.AUTHENTICATION
        )
        assert result.valid is False
    
    def test_right_to_erasure(
        self,
        consent_service: ConsentService,
        sample_user: User,
        db_session
    ):
        """DPDP: User can request data deletion (Section 12)."""
        # Create biometric data
        template = BiometricTemplate(
            user_id=sample_user.id,
            encrypted_embedding=b"biometric" * 1000,
            encryption_params_hash="test",
            is_active=True
        )
        db_session.add(template)
        db_session.commit()
        
        # Request deletion
        count = consent_service.soft_delete_biometric_data(sample_user.id)
        
        assert count == 1
        
        # Data should be soft-deleted
        db_session.refresh(template)
        assert template.is_active is False
    
    def test_consent_expiration(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str
    ):
        """DPDP: Consent has limited validity period."""
        # Grant with 30-day expiration
        result = consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=30
        )
        
        assert result.success is True
        
        # Check expiration is set correctly
        expected_expiry = datetime.now(timezone.utc) + timedelta(days=30)
        assert result.expires_at.date() == expected_expiry.date()
    
    def test_audit_trail_immutable(
        self,
        consent_service: ConsentService,
        sample_user: User,
        valid_consent_text: str,
        db_session
    ):
        """DPDP: Audit logs are immutable for compliance."""
        # Grant consent (creates audit log)
        consent_service.grant_consent(
            user_id=sample_user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text=valid_consent_text,
            expires_in_days=365
        )
        
        # Get audit log
        log = db_session.query(AuditLog).filter_by(
            user_id=sample_user.id,
            action=AuditAction.CONSENT_GRANT
        ).first()
        
        assert log is not None
        
        # Attempt to modify should fail
        log.success = False
        with pytest.raises(ValueError, match="immutable"):
            db_session.commit()


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
