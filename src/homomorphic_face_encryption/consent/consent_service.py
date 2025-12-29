"""
Consent Service Layer

Provides consent lifecycle management with:
- Consent grant with validation
- Real-time consent verification with Redis caching
- Consent revocation with session invalidation
- User data export and deletion

DPDP Act 2023 Compliance:
- Section 6: Explicit, informed consent
- Section 11: Right to withdraw consent
- Section 12: Right to erasure
- Purpose limitation: One consent per purpose

Performance:
- Consent verification <5ms with caching
- 60-second cache TTL with invalidation on revoke
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from ..database import (
    User,
    BiometricTemplate,
    ConsentRecord,
    AuditLog,
    ConsentPurpose,
    AuditAction,
    hash_consent_text,
    verify_consent_hash,
    encrypt_column_data,
    encrypt_json_metadata,
    decrypt_json_metadata,
)

logger = logging.getLogger(__name__)


@dataclass
class ConsentVerificationResult:
    """Result of consent verification check."""
    valid: bool
    consent_id: Optional[UUID] = None
    purpose: Optional[ConsentPurpose] = None
    expires_at: Optional[datetime] = None
    remaining_days: int = 0
    status: str = "unknown"  # active, expired, revoked, not_found
    cached: bool = False
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "valid": self.valid,
            "consent_id": str(self.consent_id) if self.consent_id else None,
            "purpose": self.purpose.value if self.purpose else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "remaining_days": self.remaining_days,
            "status": self.status,
        }


@dataclass
class ConsentGrantResult:
    """Result of consent grant operation."""
    success: bool
    consent_id: Optional[UUID] = None
    status: str = "unknown"
    granted_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "consent_id": str(self.consent_id) if self.consent_id else None,
            "status": self.status,
            "granted_at": self.granted_at.isoformat() if self.granted_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "error": self.error,
        }


class ConsentService:
    """
    Service for managing user consent lifecycle.
    
    Handles:
    - Grant: Create new consent record with validation
    - Verify: Check if user has valid consent (with caching)
    - Revoke: Revoke consent and invalidate sessions
    - Export: Export all user data as JSON
    - Delete: Soft-delete biometric data
    
    Usage:
        consent_service = ConsentService(db_session, redis_client)
        
        # Grant consent
        result = consent_service.grant_consent(
            user_id=user.id,
            purpose=ConsentPurpose.AUTHENTICATION,
            consent_text="I consent...",
            expires_in_days=365,
            ip_address="192.168.1.1"
        )
        
        # Verify consent
        verification = consent_service.verify_consent(
            user_id=user.id,
            purpose=ConsentPurpose.AUTHENTICATION
        )
    """
    
    # Cache configuration
    CACHE_TTL_SECONDS = 60
    CACHE_KEY_PREFIX = "consent_cache"
    SESSION_KEY_PREFIX = "session"
    
    def __init__(self, db: Session, redis_client=None):
        """
        Initialize consent service.
        
        Args:
            db: SQLAlchemy database session
            redis_client: Redis client for caching (optional)
        """
        self.db = db
        self.redis = redis_client
    
    def _get_cache_key(self, user_id: UUID, purpose: ConsentPurpose) -> str:
        """Generate Redis cache key for consent verification."""
        return f"{self.CACHE_KEY_PREFIX}:{user_id}:{purpose.value}"
    
    def _get_from_cache(self, user_id: UUID, purpose: ConsentPurpose) -> Optional[ConsentVerificationResult]:
        """Get consent verification result from cache."""
        if not self.redis:
            return None
        
        try:
            key = self._get_cache_key(user_id, purpose)
            cached = self.redis.get(key)
            
            if cached:
                data = json.loads(cached)
                return ConsentVerificationResult(
                    valid=data["valid"],
                    consent_id=UUID(data["consent_id"]) if data.get("consent_id") else None,
                    purpose=ConsentPurpose(data["purpose"]) if data.get("purpose") else None,
                    expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
                    remaining_days=data.get("remaining_days", 0),
                    status=data.get("status", "cached"),
                    cached=True
                )
        except Exception as e:
            logger.warning(f"Cache read error: {e}")
        
        return None
    
    def _set_cache(self, user_id: UUID, purpose: ConsentPurpose, result: ConsentVerificationResult) -> None:
        """Store consent verification result in cache."""
        if not self.redis:
            return
        
        try:
            key = self._get_cache_key(user_id, purpose)
            data = {
                "valid": result.valid,
                "consent_id": str(result.consent_id) if result.consent_id else None,
                "purpose": result.purpose.value if result.purpose else None,
                "expires_at": result.expires_at.isoformat() if result.expires_at else None,
                "remaining_days": result.remaining_days,
                "status": result.status,
            }
            self.redis.setex(key, self.CACHE_TTL_SECONDS, json.dumps(data))
        except Exception as e:
            logger.warning(f"Cache write error: {e}")
    
    def invalidate_consent_cache(self, user_id: UUID, purpose: Optional[ConsentPurpose] = None) -> None:
        """
        Invalidate consent cache for user.
        
        Called after consent revocation to ensure immediate effect.
        
        Args:
            user_id: User whose cache to invalidate
            purpose: Specific purpose to invalidate (or all if None)
        """
        if not self.redis:
            return
        
        try:
            if purpose:
                # Invalidate specific purpose
                key = self._get_cache_key(user_id, purpose)
                self.redis.delete(key)
            else:
                # Invalidate all purposes for user
                for p in ConsentPurpose:
                    key = self._get_cache_key(user_id, p)
                    self.redis.delete(key)
            
            # Publish invalidation event for distributed systems
            self.redis.publish(
                "consent_invalidation",
                json.dumps({
                    "user_id": str(user_id),
                    "purpose": purpose.value if purpose else "all"
                })
            )
        except Exception as e:
            logger.warning(f"Cache invalidation error: {e}")
    
    def grant_consent(
        self,
        user_id: UUID,
        purpose: ConsentPurpose,
        consent_text: str,
        expires_in_days: int = 365,
        ip_address: Optional[str] = None
    ) -> ConsentGrantResult:
        """
        Grant consent for a specific purpose.
        
        DPDP Compliance:
        - Validates consent text is not empty (min 100 chars)
        - Ensures no duplicate active consent for same purpose
        - Hashes consent text for tamper detection
        - Encrypts IP address for pseudonymization
        
        Args:
            user_id: UUID of the user granting consent
            purpose: Purpose for which consent is granted
            consent_text: Full text of consent shown to user
            expires_in_days: Days until consent expires (1-365)
            ip_address: User's IP address (will be encrypted)
        
        Returns:
            ConsentGrantResult with success status and consent_id
        """
        # Validate inputs
        if not consent_text or len(consent_text.strip()) < 100:
            return ConsentGrantResult(
                success=False,
                status="invalid_consent_text",
                error="Consent text must be at least 100 characters"
            )
        
        if not 1 <= expires_in_days <= 365:
            return ConsentGrantResult(
                success=False,
                status="invalid_expiration",
                error="Expiration must be between 1 and 365 days"
            )
        
        # Check user exists
        user = self.db.query(User).filter_by(id=user_id, is_active=True).first()
        if not user:
            return ConsentGrantResult(
                success=False,
                status="user_not_found",
                error="User not found or inactive"
            )
        
        # Check for existing active consent for this purpose
        existing = self.db.query(ConsentRecord).filter_by(
            user_id=user_id,
            purpose=purpose,
            is_revoked=False
        ).first()
        
        if existing and existing.is_valid:
            return ConsentGrantResult(
                success=False,
                status="duplicate_consent",
                error=f"Active consent already exists for {purpose.value}"
            )
        
        try:
            # Create consent record
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(days=expires_in_days)
            
            consent = ConsentRecord(
                user_id=user_id,
                purpose=purpose,
                consent_text_hash=hash_consent_text(consent_text),
                ip_address_encrypted=ip_address,  # PGPEncryptedType handles encryption
                consent_granted_at=now,
                consent_expires_at=expires_at,
                is_revoked=False
            )
            
            self.db.add(consent)
            
            # Create audit log entry
            audit_metadata = {
                "purpose": purpose.value,
                "expires_in_days": expires_in_days,
                "consent_text_length": len(consent_text),
                "ip_address": ip_address  # Will be encrypted by EncryptedJSONType
            }
            
            audit_log = AuditLog(
                user_id=user_id,
                action=AuditAction.CONSENT_GRANT,
                metadata_encrypted=encrypt_json_metadata(audit_metadata),
                success=True
            )
            self.db.add(audit_log)
            
            self.db.commit()
            
            # Invalidate any cached "not found" results
            self.invalidate_consent_cache(user_id, purpose)
            
            logger.info(f"Consent granted: user={user_id}, purpose={purpose.value}")
            
            return ConsentGrantResult(
                success=True,
                consent_id=consent.id,
                status="active",
                granted_at=consent.consent_granted_at,
                expires_at=consent.consent_expires_at
            )
            
        except IntegrityError as e:
            self.db.rollback()
            logger.error(f"Consent grant failed (integrity): {e}")
            return ConsentGrantResult(
                success=False,
                status="database_error",
                error="Could not create consent record"
            )
        except Exception as e:
            self.db.rollback()
            logger.error(f"Consent grant failed: {e}")
            return ConsentGrantResult(
                success=False,
                status="error",
                error="Internal error during consent grant"
            )
    
    def verify_consent(
        self,
        user_id: UUID,
        purpose: ConsentPurpose,
        use_cache: bool = True
    ) -> ConsentVerificationResult:
        """
        Verify if user has valid consent for a purpose.
        
        Performance: <5ms with caching (80% cache hit expected)
        
        Args:
            user_id: UUID of the user
            purpose: Purpose to check consent for
            use_cache: Whether to use Redis cache
        
        Returns:
            ConsentVerificationResult with validity status
        """
        # Check cache first
        if use_cache:
            cached = self._get_from_cache(user_id, purpose)
            if cached:
                return cached
        
        # Query database
        consent = self.db.query(ConsentRecord).filter_by(
            user_id=user_id,
            purpose=purpose,
            is_revoked=False
        ).first()
        
        if not consent:
            result = ConsentVerificationResult(
                valid=False,
                status="not_found"
            )
        elif consent.is_expired:
            result = ConsentVerificationResult(
                valid=False,
                consent_id=consent.id,
                purpose=purpose,
                expires_at=consent.consent_expires_at,
                remaining_days=0,
                status="expired"
            )
        else:
            result = ConsentVerificationResult(
                valid=True,
                consent_id=consent.id,
                purpose=purpose,
                expires_at=consent.consent_expires_at,
                remaining_days=consent.remaining_days,
                status="active"
            )
        
        # Cache result
        if use_cache:
            self._set_cache(user_id, purpose, result)
        
        return result
    
    def revoke_consent(
        self,
        consent_id: UUID,
        user_id: UUID,
        reason: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Revoke a consent record.
        
        Side Effects:
        - Sets is_revoked=True, revoked_at=now
        - Invalidates all user sessions in Redis
        - Soft-deletes biometric templates if AUTH consent revoked
        - Creates audit log entry
        
        Args:
            consent_id: UUID of consent to revoke
            user_id: UUID of user (for authorization check)
            reason: Optional revocation reason
            ip_address: User's IP for audit
        
        Returns:
            bool: True if revocation successful
        """
        # Find consent record
        consent = self.db.query(ConsentRecord).filter_by(
            id=consent_id,
            user_id=user_id,  # Authorization: user can only revoke own consent
            is_revoked=False
        ).first()
        
        if not consent:
            logger.warning(f"Consent revocation failed: not found or already revoked")
            return False
        
        try:
            now = datetime.now(timezone.utc)
            purpose = consent.purpose
            
            # Update consent record
            consent.is_revoked = True
            consent.revoked_at = now
            consent.revocation_reason = reason
            
            # If authentication consent revoked, soft-delete biometric templates
            if purpose == ConsentPurpose.AUTHENTICATION:
                templates = self.db.query(BiometricTemplate).filter_by(
                    user_id=user_id,
                    is_active=True
                ).all()
                
                for template in templates:
                    template.is_active = False
                
                logger.info(f"Soft-deleted {len(templates)} biometric templates")
            
            # Create audit log
            audit_metadata = {
                "consent_id": str(consent_id),
                "purpose": purpose.value,
                "reason": reason,
                "ip_address": ip_address
            }
            
            audit_log = AuditLog(
                user_id=user_id,
                action=AuditAction.CONSENT_REVOKE,
                metadata_encrypted=encrypt_json_metadata(audit_metadata),
                success=True
            )
            self.db.add(audit_log)
            
            self.db.commit()
            
            # Invalidate consent cache
            self.invalidate_consent_cache(user_id, purpose)
            
            # Invalidate all user sessions
            self._invalidate_user_sessions(user_id)
            
            logger.info(f"Consent revoked: user={user_id}, purpose={purpose.value}")
            return True
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Consent revocation failed: {e}")
            return False
    
    def _invalidate_user_sessions(self, user_id: UUID) -> int:
        """
        Invalidate all sessions for a user in Redis.
        
        Returns:
            int: Number of sessions invalidated
        """
        if not self.redis:
            return 0
        
        try:
            # Find all session keys for user
            pattern = f"{self.SESSION_KEY_PREFIX}:{user_id}:*"
            keys = list(self.redis.scan_iter(match=pattern))
            
            if keys:
                self.redis.delete(*keys)
                logger.info(f"Invalidated {len(keys)} sessions for user {user_id}")
                
                # Create audit log for session invalidation
                audit_log = AuditLog(
                    user_id=user_id,
                    action=AuditAction.SESSION_INVALIDATE,
                    metadata_encrypted=encrypt_json_metadata({
                        "sessions_invalidated": len(keys)
                    }),
                    success=True
                )
                self.db.add(audit_log)
                self.db.commit()
            
            return len(keys)
        except Exception as e:
            logger.warning(f"Session invalidation error: {e}")
            return 0
    
    def get_user_consents(self, user_id: UUID, include_revoked: bool = False) -> list[dict]:
        """
        Get all consent records for a user.
        
        Args:
            user_id: UUID of the user
            include_revoked: Whether to include revoked consents
        
        Returns:
            List of consent record dictionaries
        """
        query = self.db.query(ConsentRecord).filter_by(user_id=user_id)
        
        if not include_revoked:
            query = query.filter_by(is_revoked=False)
        
        consents = query.order_by(ConsentRecord.consent_granted_at.desc()).all()
        
        return [
            {
                "consent_id": str(c.id),
                "purpose": c.purpose.value,
                "granted_at": c.consent_granted_at.isoformat(),
                "expires_at": c.consent_expires_at.isoformat(),
                "is_revoked": c.is_revoked,
                "revoked_at": c.revoked_at.isoformat() if c.revoked_at else None,
                "is_valid": c.is_valid,
                "remaining_days": c.remaining_days
            }
            for c in consents
        ]
    
    def get_dashboard_data(self, user_id: UUID, page: int = 1, per_page: int = 20) -> dict:
        """
        Get comprehensive dashboard data for a user.
        
        Includes:
        - Active consents
        - Revoked consents
        - Authentication history
        - Data summary statistics
        
        Args:
            user_id: UUID of the user
            page: Page number for pagination
            per_page: Records per page
        
        Returns:
            Dashboard data dictionary
        """
        # Get user
        user = self.db.query(User).filter_by(id=user_id).first()
        if not user:
            return {"error": "User not found"}
        
        # Get active consents
        active_consents = self.get_user_consents(user_id, include_revoked=False)
        
        # Get revoked consents
        revoked = self.db.query(ConsentRecord).filter_by(
            user_id=user_id,
            is_revoked=True
        ).order_by(ConsentRecord.revoked_at.desc()).limit(10).all()
        
        revoked_consents = [
            {
                "consent_id": str(c.id),
                "purpose": c.purpose.value,
                "granted_at": c.consent_granted_at.isoformat(),
                "revoked_at": c.revoked_at.isoformat() if c.revoked_at else None,
                "reason": c.revocation_reason
            }
            for c in revoked
        ]
        
        # Get authentication history with pagination
        offset = (page - 1) * per_page
        auth_actions = [
            AuditAction.AUTHENTICATE_SUCCESS,
            AuditAction.AUTHENTICATE_FAIL
        ]
        
        auth_logs = self.db.query(AuditLog).filter(
            AuditLog.user_id == user_id,
            AuditLog.action.in_(auth_actions)
        ).order_by(
            AuditLog.timestamp.desc()
        ).offset(offset).limit(per_page).all()
        
        auth_history = []
        for log in auth_logs:
            entry = {
                "timestamp": log.timestamp.isoformat(),
                "result": "success" if log.success else "failure",
                "action": log.action.value
            }
            
            # Decrypt metadata if available
            if log.metadata_encrypted:
                try:
                    metadata = decrypt_json_metadata(log.metadata_encrypted)
                    entry["location"] = metadata.get("location", "Unknown")
                    entry["device"] = metadata.get("user_agent_hash", "Unknown")
                except Exception:
                    pass
            
            auth_history.append(entry)
        
        # Calculate statistics
        total_auths = self.db.query(AuditLog).filter(
            AuditLog.user_id == user_id,
            AuditLog.action.in_(auth_actions)
        ).count()
        
        success_auths = self.db.query(AuditLog).filter(
            AuditLog.user_id == user_id,
            AuditLog.action == AuditAction.AUTHENTICATE_SUCCESS
        ).count()
        
        success_rate = (success_auths / total_auths) if total_auths > 0 else 0
        
        return {
            "user": {
                "id": str(user.id),
                "username": user.username,
                "created_at": user.created_at.isoformat(),
                "last_authentication": user.last_authentication.isoformat() if user.last_authentication else None
            },
            "active_consents": active_consents,
            "revoked_consents": revoked_consents,
            "authentication_history": auth_history,
            "data_summary": {
                "total_authentications": total_auths,
                "successful_authentications": success_auths,
                "success_rate": round(success_rate, 3),
                "last_authentication": user.last_authentication.isoformat() if user.last_authentication else None
            },
            "pagination": {
                "page": page,
                "per_page": per_page,
                "has_more": len(auth_history) == per_page
            }
        }
    
    def export_user_data(self, user_id: UUID) -> dict:
        """
        Export all user data as JSON for DPDP data portability.
        
        Includes:
        - User profile
        - All consent records
        - Full audit log
        - Metadata
        
        NOTE: Encrypted biometric templates are NOT exported
        (they are user-specific and not portable)
        
        Args:
            user_id: UUID of the user
        
        Returns:
            Complete user data dictionary
        """
        user = self.db.query(User).filter_by(id=user_id).first()
        if not user:
            return {"error": "User not found"}
        
        # Export user profile
        profile = {
            "id": str(user.id),
            "username": user.username,
            "created_at": user.created_at.isoformat(),
            "last_authentication": user.last_authentication.isoformat() if user.last_authentication else None,
            "consent_version": user.consent_version,
            "is_active": user.is_active
        }
        
        # Export all consent records
        consents = self.get_user_consents(user_id, include_revoked=True)
        
        # Export audit logs
        audit_logs = self.db.query(AuditLog).filter_by(
            user_id=user_id
        ).order_by(AuditLog.timestamp.desc()).all()
        
        audit_export = []
        for log in audit_logs:
            entry = {
                "id": str(log.id),
                "action": log.action.value,
                "timestamp": log.timestamp.isoformat(),
                "success": log.success,
                "error_message": log.error_message
            }
            
            # Include decrypted metadata
            if log.metadata_encrypted:
                try:
                    entry["metadata"] = decrypt_json_metadata(log.metadata_encrypted)
                except Exception:
                    entry["metadata"] = {"note": "encrypted"}
            
            audit_export.append(entry)
        
        # Count biometric templates (not exported)
        template_count = self.db.query(BiometricTemplate).filter_by(
            user_id=user_id
        ).count()
        
        # Create audit log for export
        audit_log = AuditLog(
            user_id=user_id,
            action=AuditAction.DATA_EXPORT,
            metadata_encrypted=encrypt_json_metadata({
                "export_type": "full",
                "records_exported": {
                    "consents": len(consents),
                    "audit_logs": len(audit_export)
                }
            }),
            success=True
        )
        self.db.add(audit_log)
        self.db.commit()
        
        return {
            "export_date": datetime.now(timezone.utc).isoformat(),
            "user": profile,
            "consent_records": consents,
            "audit_logs": audit_export,
            "biometric_templates": {
                "count": template_count,
                "note": "Encrypted biometric templates are not exported for security"
            }
        }
    
    def soft_delete_biometric_data(
        self,
        user_id: UUID,
        ip_address: Optional[str] = None
    ) -> int:
        """
        Soft-delete all biometric data for a user.
        
        DPDP Compliance:
        - Right to erasure (Section 12)
        - Soft delete for 30-day grace period
        - Hard deletion scheduled separately
        
        Args:
            user_id: UUID of the user
            ip_address: User's IP for audit
        
        Returns:
            Number of templates soft-deleted
        """
        templates = self.db.query(BiometricTemplate).filter_by(
            user_id=user_id,
            is_active=True
        ).all()
        
        count = 0
        for template in templates:
            template.is_active = False
            count += 1
        
        # Revoke all consents
        consents = self.db.query(ConsentRecord).filter_by(
            user_id=user_id,
            is_revoked=False
        ).all()
        
        now = datetime.now(timezone.utc)
        for consent in consents:
            consent.is_revoked = True
            consent.revoked_at = now
            consent.revocation_reason = "User requested data deletion"
        
        # Create audit log
        audit_log = AuditLog(
            user_id=user_id,
            action=AuditAction.DATA_DELETE,
            metadata_encrypted=encrypt_json_metadata({
                "templates_deleted": count,
                "consents_revoked": len(consents),
                "ip_address": ip_address,
                "hard_delete_scheduled": (now + timedelta(days=30)).isoformat()
            }),
            success=True
        )
        self.db.add(audit_log)
        
        self.db.commit()
        
        # Invalidate sessions and caches
        self._invalidate_user_sessions(user_id)
        self.invalidate_consent_cache(user_id)
        
        logger.info(f"Soft-deleted biometric data: user={user_id}, templates={count}")
        
        return count
