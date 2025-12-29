"""
Consent Management for DPDP Compliance.

Updated manager that integrates with the new consent service layer.
Maintains backward compatibility with existing code while adding
new DPDP-compliant features.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from ..database import (
    ConsentRecord,
    AuditLog,
    ConsentPurpose,
    AuditAction,
    User,
    SessionLocal,
    hash_consent_text,
    encrypt_json_metadata,
)
from .consent_service import ConsentService, ConsentVerificationResult


logger = logging.getLogger(__name__)


class ConsentManager:
    """
    High-level consent management interface.
    
    This class provides a simplified interface for consent operations,
    delegating to ConsentService for implementation.
    
    For new code, prefer using ConsentService directly.
    
    Usage:
        manager = ConsentManager()
        
        # Check consent
        if manager.has_valid_consent(user_id, ConsentPurpose.AUTHENTICATION):
            # Proceed with authentication
            pass
        
        # Grant consent
        manager.grant_consent(
            user_id=user_id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text="I consent to...",
            ip_address=request.remote_addr
        )
    """
    
    def __init__(self, db_session: Optional[Session] = None, redis_client=None):
        """
        Initialize consent manager.
        
        Args:
            db_session: SQLAlchemy session (creates new if None)
            redis_client: Redis client for caching
        """
        self._db = db_session
        self._owns_session = db_session is None
        self.redis = redis_client
        self._service: Optional[ConsentService] = None
    
    @property
    def db(self) -> Session:
        """Get database session, creating if needed."""
        if self._db is None:
            self._db = SessionLocal()
        return self._db
    
    @property
    def service(self) -> ConsentService:
        """Get consent service instance."""
        if self._service is None:
            self._service = ConsentService(self.db, self.redis)
        return self._service
    
    def close(self):
        """Close database session if we own it."""
        if self._owns_session and self._db is not None:
            self._db.close()
            self._db = None
            self._service = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def has_valid_consent(
        self,
        user_id: UUID,
        purpose: ConsentPurpose,
        use_cache: bool = True
    ) -> bool:
        """
        Check if user has valid consent for a purpose.
        
        This is the primary method for consent verification in request handlers.
        
        Args:
            user_id: UUID of the user
            purpose: Purpose to check
            use_cache: Whether to use Redis cache
        
        Returns:
            True if user has valid (active, non-expired) consent
        """
        result = self.service.verify_consent(user_id, purpose, use_cache)
        return result.valid
    
    def verify_consent(
        self,
        user_id: UUID,
        purpose: ConsentPurpose
    ) -> ConsentVerificationResult:
        """
        Get detailed consent verification result.
        
        Args:
            user_id: UUID of the user
            purpose: Purpose to check
        
        Returns:
            ConsentVerificationResult with full details
        """
        return self.service.verify_consent(user_id, purpose)
    
    def grant_consent(
        self,
        user_id: UUID,
        purpose: ConsentPurpose,
        consent_text: str,
        expires_in_days: int = 365,
        ip_address: Optional[str] = None
    ) -> dict:
        """
        Grant consent for a user.
        
        Args:
            user_id: UUID of the user
            purpose: Purpose for consent
            consent_text: Full consent text shown to user
            expires_in_days: Validity period
            ip_address: User's IP for audit
        
        Returns:
            Result dictionary with success status and details
        """
        result = self.service.grant_consent(
            user_id=user_id,
            purpose=purpose,
            consent_text=consent_text,
            expires_in_days=expires_in_days,
            ip_address=ip_address
        )
        return result.to_dict()
    
    def revoke_consent(
        self,
        consent_id: UUID,
        user_id: UUID,
        reason: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Revoke a consent.
        
        Args:
            consent_id: UUID of consent to revoke
            user_id: UUID of user (for authorization)
            reason: Optional revocation reason
            ip_address: User's IP for audit
        
        Returns:
            True if revocation successful
        """
        return self.service.revoke_consent(
            consent_id=consent_id,
            user_id=user_id,
            reason=reason,
            ip_address=ip_address
        )
    
    def get_user_consents(self, user_id: UUID, include_revoked: bool = False) -> list:
        """Get all consents for a user."""
        return self.service.get_user_consents(user_id, include_revoked)
    
    def get_consent_history(self, user_id: UUID) -> list:
        """
        Get consent change history for a user.
        
        Backward compatibility with old API.
        """
        consents = self.service.get_user_consents(user_id, include_revoked=True)
        
        history = []
        for c in consents:
            history.append({
                "action": "granted",
                "purpose": c["purpose"],
                "timestamp": c["granted_at"]
            })
            if c["is_revoked"]:
                history.append({
                    "action": "revoked",
                    "purpose": c["purpose"],
                    "timestamp": c["revoked_at"]
                })
        
        # Sort by timestamp
        history.sort(key=lambda x: x["timestamp"], reverse=True)
        return history
    
    def revoke_consent_and_delete_data(self, user_id: UUID) -> dict:
        """
        Revoke all consents and delete user data.
        
        Backward compatibility method. For new code, use:
        - service.revoke_consent() for individual consents
        - service.soft_delete_biometric_data() for data deletion
        """
        # Soft delete biometric data
        count = self.service.soft_delete_biometric_data(user_id)
        
        return {
            "message": f"Data for user {user_id} has been scheduled for deletion",
            "templates_affected": count,
            "status": "soft_deleted",
            "hard_deletion_in_days": 30
        }
    
    # Convenience methods for specific purposes
    
    def has_authentication_consent(self, user_id: UUID) -> bool:
        """Check if user has valid authentication consent."""
        return self.has_valid_consent(user_id, ConsentPurpose.AUTHENTICATION)
    
    def has_access_control_consent(self, user_id: UUID) -> bool:
        """Check if user has valid access control consent."""
        return self.has_valid_consent(user_id, ConsentPurpose.ACCESS_CONTROL)
    
    def has_audit_consent(self, user_id: UUID) -> bool:
        """Check if user has valid audit consent."""
        return self.has_valid_consent(user_id, ConsentPurpose.AUDIT)


# Default consent text templates for DPDP compliance
# These should be customized and localized for production

CONSENT_TEXT_AUTHENTICATION = """
BIOMETRIC AUTHENTICATION CONSENT

I understand and consent to the following:

1. PURPOSE: My biometric data (facial features) will be used solely for 
   identity verification and authentication purposes.

2. DATA COLLECTION: A mathematical representation (embedding) of my facial 
   features will be created and encrypted using homomorphic encryption.

3. ENCRYPTION: My biometric data is encrypted at all times. Only encrypted 
   comparisons are performed; my actual facial features are never decoded 
   by the system.

4. RETENTION: My encrypted biometric template will be stored until I revoke 
   consent or request deletion.

5. RIGHTS: Under the Digital Personal Data Protection Act 2023, I have the 
   right to:
   - Withdraw this consent at any time
   - Request deletion of my biometric data
   - Request a copy of my personal data
   - File a complaint with the Data Protection Board

6. WITHDRAWAL: I can revoke this consent at any time through the consent 
   dashboard, which will immediately prevent further biometric authentication 
   and schedule deletion of my biometric templates.

By granting this consent, I confirm that I have read, understood, and agree 
to the above terms.
"""

CONSENT_TEXT_ACCESS_CONTROL = """
ACCESS CONTROL CONSENT

I understand and consent to the following:

1. PURPOSE: My biometric data will be used for physical access control 
   systems, including building entry and restricted area access.

2. LOGGING: Each access attempt (successful or failed) will be logged for 
   security purposes, including timestamp and location.

3. RETENTION: Access logs will be retained for security audit purposes as 
   required by applicable regulations.

4. RIGHTS: I retain all rights under the DPDP Act 2023, including the right 
   to withdraw consent and request data deletion.

By granting this consent, I confirm that I have read and agree to these terms.
"""

CONSENT_TEXT_AUDIT = """
AUDIT LOGGING CONSENT

I understand and consent to the following:

1. PURPOSE: Detailed logs of my authentication activities will be maintained 
   for security auditing and compliance purposes.

2. DATA COLLECTED: Logs include timestamp, action type, success/failure 
   status, and pseudonymized location information.

3. RETENTION: Audit logs will be retained for 7 years as required by 
   regulatory compliance.

4. ACCESS: Audit logs may be accessed by authorized security personnel and 
   regulators as required.

By granting this consent, I confirm that I have read and agree to these terms.
"""
