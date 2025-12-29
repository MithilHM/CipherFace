"""
Consent Management Module for DPDP-Compliant Privacy-Preserving Facial Recognition

This module provides:
- ConsentService: Core consent lifecycle management
- ConsentManager: High-level convenience interface
- Consent text templates for DPDP compliance

DPDP Act 2023 Compliance:
- Section 6: Explicit, informed consent with purpose limitation
- Section 11: Right to withdraw consent at any time
- Section 12: Right to erasure
- Section 13: Right to data portability
- Section 15: Breach notification capability

Usage:
    from homomorphic_face_encryption.consent import (
        ConsentService,
        ConsentManager,
        ConsentPurpose,
        CONSENT_TEXT_AUTHENTICATION,
    )
    
    # Using ConsentService directly
    service = ConsentService(db_session, redis_client)
    result = service.verify_consent(user_id, ConsentPurpose.AUTHENTICATION)
    
    # Using ConsentManager convenience interface
    with ConsentManager(db_session) as manager:
        if manager.has_valid_consent(user_id, ConsentPurpose.AUTHENTICATION):
            # Proceed with biometric operation
            pass
"""

from .consent_service import (
    ConsentService,
    ConsentVerificationResult,
    ConsentGrantResult,
)

from .manager import (
    ConsentManager,
    CONSENT_TEXT_AUTHENTICATION,
    CONSENT_TEXT_ACCESS_CONTROL,
    CONSENT_TEXT_AUDIT,
)

# Re-export ConsentPurpose for convenience
from ..database import ConsentPurpose

__all__ = [
    # Service layer
    "ConsentService",
    "ConsentVerificationResult",
    "ConsentGrantResult",
    
    # Manager layer
    "ConsentManager",
    
    # Consent text templates
    "CONSENT_TEXT_AUTHENTICATION",
    "CONSENT_TEXT_ACCESS_CONTROL",
    "CONSENT_TEXT_AUDIT",
    
    # Enums
    "ConsentPurpose",
]
