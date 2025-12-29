"""
Consent Management API Routes

Flask Blueprint providing DPDP-compliant consent management endpoints:
- POST /api/consent/grant - Grant consent for a purpose
- GET /api/consent/verify/<user_id>/<purpose> - Verify consent status
- POST /api/consent/revoke - Revoke a consent
- GET /api/consent/dashboard/<user_id> - Get user consent dashboard
- POST /api/consent/export-data - Export all user data
- POST /api/consent/delete-biometric-data - Soft-delete biometric data

All endpoints require JWT authentication.
"""

import logging
from uuid import UUID

from flask import Blueprint, request, jsonify, g, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity

from ..database import (
    ConsentPurpose,
    SessionLocal,
)
from ..consent.consent_service import ConsentService
from ..consent.manager import (
    CONSENT_TEXT_AUTHENTICATION,
    CONSENT_TEXT_ACCESS_CONTROL,
    CONSENT_TEXT_AUDIT,
)

logger = logging.getLogger(__name__)

consent_bp = Blueprint('consent', __name__)


def get_db():
    """Get database session for request."""
    if 'db' not in g:
        g.db = SessionLocal()
    return g.db


def get_redis():
    """Get Redis client from app config."""
    from flask import current_app
    return current_app.config.get('REDIS_CLIENT')


def get_consent_service():
    """Get consent service for request."""
    if 'consent_service' not in g:
        g.consent_service = ConsentService(get_db(), get_redis())
    return g.consent_service


@consent_bp.teardown_app_request
def cleanup_db(exception=None):
    """Close database session after request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def parse_uuid(value: str, field_name: str = "id") -> UUID:
    """Parse UUID from string, raising ValueError with descriptive message."""
    try:
        return UUID(value)
    except (ValueError, AttributeError):
        raise ValueError(f"Invalid {field_name}: must be a valid UUID")


def get_client_ip() -> str:
    """Get client IP address from request."""
    # Check for proxy headers
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr or "unknown"


# ============================================================================
# Consent Grant Endpoint
# ============================================================================

@consent_bp.route('/grant', methods=['POST'])
@jwt_required()
def grant_consent():
    """
    Grant consent for a specific purpose.
    
    Request Body:
        {
            "user_id": "uuid",
            "purpose": "AUTHENTICATION | ACCESS_CONTROL | AUDIT",
            "consent_text": "Full consent text (min 100 chars)",
            "expires_in_days": 365 (optional, default 365)
        }
    
    Response:
        {
            "success": true,
            "consent_id": "uuid",
            "status": "active",
            "granted_at": "ISO8601",
            "expires_at": "ISO8601"
        }
    
    Errors:
        400 - Invalid request body
        403 - User can only grant own consent
        409 - Active consent already exists for purpose
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        # Parse and validate user_id
        user_id_str = data.get('user_id')
        if not user_id_str:
            return jsonify({"error": "user_id is required"}), 400
        
        user_id = parse_uuid(user_id_str, "user_id")
        
        # Authorization: user can only grant own consent
        jwt_user_id = get_jwt_identity()
        if str(user_id) != str(jwt_user_id):
            return jsonify({"error": "Cannot grant consent for another user"}), 403
        
        # Parse purpose
        purpose_str = data.get('purpose')
        if not purpose_str:
            return jsonify({"error": "purpose is required"}), 400
        
        try:
            purpose = ConsentPurpose(purpose_str.upper())
        except ValueError:
            valid_purposes = [p.value for p in ConsentPurpose]
            return jsonify({
                "error": f"Invalid purpose. Must be one of: {valid_purposes}"
            }), 400
        
        # Get consent text (use template if not provided)
        consent_text = data.get('consent_text')
        if not consent_text:
            # Use default template based on purpose
            templates = {
                ConsentPurpose.AUTHENTICATION: CONSENT_TEXT_AUTHENTICATION,
                ConsentPurpose.ACCESS_CONTROL: CONSENT_TEXT_ACCESS_CONTROL,
                ConsentPurpose.AUDIT: CONSENT_TEXT_AUDIT,
            }
            consent_text = templates.get(purpose, CONSENT_TEXT_AUTHENTICATION)
        
        # Get expiration
        expires_in_days = data.get('expires_in_days', 365)
        try:
            expires_in_days = int(expires_in_days)
        except (ValueError, TypeError):
            return jsonify({"error": "expires_in_days must be an integer"}), 400
        
        # Grant consent
        service = get_consent_service()
        result = service.grant_consent(
            user_id=user_id,
            purpose=purpose,
            consent_text=consent_text,
            expires_in_days=expires_in_days,
            ip_address=get_client_ip()
        )
        
        if result.success:
            return jsonify(result.to_dict()), 201
        else:
            status_code = 409 if result.status == "duplicate_consent" else 400
            return jsonify(result.to_dict()), status_code
            
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Consent grant error")
        return jsonify({"error": "Internal server error"}), 500


# ============================================================================
# Consent Verification Endpoint
# ============================================================================

@consent_bp.route('/verify/<user_id>/<purpose>', methods=['GET'])
@jwt_required()
def verify_consent(user_id: str, purpose: str):
    """
    Verify if user has valid consent for a purpose.
    
    Path Parameters:
        user_id: UUID of the user
        purpose: AUTHENTICATION | ACCESS_CONTROL | AUDIT
    
    Response:
        {
            "valid": true,
            "consent_id": "uuid",
            "purpose": "AUTHENTICATION",
            "expires_at": "ISO8601",
            "remaining_days": 42,
            "status": "active"
        }
    
    Performance: <5ms with caching (80% cache hit expected)
    """
    try:
        # Parse user_id
        uid = parse_uuid(user_id, "user_id")
        
        # Parse purpose
        try:
            consent_purpose = ConsentPurpose(purpose.upper())
        except ValueError:
            valid_purposes = [p.value for p in ConsentPurpose]
            return jsonify({
                "error": f"Invalid purpose. Must be one of: {valid_purposes}"
            }), 400
        
        # Verify consent
        service = get_consent_service()
        result = service.verify_consent(uid, consent_purpose)
        
        return jsonify(result.to_dict()), 200
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Consent verification error")
        return jsonify({"error": "Internal server error"}), 500


# ============================================================================
# Consent Revocation Endpoint
# ============================================================================

@consent_bp.route('/revoke', methods=['POST'])
@jwt_required()
def revoke_consent():
    """
    Revoke a consent.
    
    Request Body:
        {
            "consent_id": "uuid",
            "revocation_reason": "Optional reason" (optional)
        }
    
    Response:
        {
            "success": true,
            "status": "revoked",
            "revoked_at": "ISO8601"
        }
    
    Side Effects:
        - Sets consent as revoked
        - Invalidates all user sessions
        - If AUTH consent: soft-deletes biometric templates
        - Creates audit log entry
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        # Parse consent_id
        consent_id_str = data.get('consent_id')
        if not consent_id_str:
            return jsonify({"error": "consent_id is required"}), 400
        
        consent_id = parse_uuid(consent_id_str, "consent_id")
        
        # Get user from JWT
        jwt_user_id = get_jwt_identity()
        user_id = parse_uuid(jwt_user_id, "jwt_user_id")
        
        # Get optional reason
        reason = data.get('revocation_reason')
        
        # Revoke consent
        service = get_consent_service()
        success = service.revoke_consent(
            consent_id=consent_id,
            user_id=user_id,
            reason=reason,
            ip_address=get_client_ip()
        )
        
        if success:
            from datetime import datetime, timezone
            return jsonify({
                "success": True,
                "status": "revoked",
                "revoked_at": datetime.now(timezone.utc).isoformat()
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": "Consent not found or already revoked"
            }), 404
            
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Consent revocation error")
        return jsonify({"error": "Internal server error"}), 500


# ============================================================================
# Consent Dashboard Endpoint
# ============================================================================

@consent_bp.route('/dashboard/<user_id>', methods=['GET'])
@jwt_required()
def get_dashboard(user_id: str):
    """
    Get consent dashboard data for a user.
    
    Path Parameters:
        user_id: UUID of the user
    
    Query Parameters:
        page: Page number (default 1)
        per_page: Records per page (default 20, max 100)
    
    Response:
        {
            "user": { ... },
            "active_consents": [ ... ],
            "revoked_consents": [ ... ],
            "authentication_history": [ ... ],
            "data_summary": { ... },
            "pagination": { ... }
        }
    
    Authorization: User can only view own dashboard
    """
    try:
        # Parse user_id
        uid = parse_uuid(user_id, "user_id")
        
        # Authorization check
        jwt_user_id = get_jwt_identity()
        if str(uid) != str(jwt_user_id):
            return jsonify({"error": "Cannot view another user's dashboard"}), 403
        
        # Get pagination params
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Get dashboard data
        service = get_consent_service()
        data = service.get_dashboard_data(uid, page=page, per_page=per_page)
        
        if "error" in data:
            return jsonify(data), 404
        
        return jsonify(data), 200
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Dashboard error")
        return jsonify({"error": "Internal server error"}), 500


# ============================================================================
# Data Export Endpoint
# ============================================================================

@consent_bp.route('/export-data', methods=['POST'])
@jwt_required()
def export_data():
    """
    Export all user data as JSON.
    
    DPDP Compliance: Data portability (Section 13)
    
    Request Body:
        {
            "confirm": true
        }
    
    Response: JSON file download containing all user data
    
    Note: Encrypted biometric templates are NOT included for security.
    """
    try:
        data = request.get_json() or {}
        
        # Require confirmation
        if not data.get('confirm'):
            return jsonify({
                "error": "Confirmation required",
                "message": "Include 'confirm': true to export data"
            }), 400
        
        # Get user from JWT
        jwt_user_id = get_jwt_identity()
        user_id = parse_uuid(jwt_user_id, "jwt_user_id")
        
        # Export data
        service = get_consent_service()
        export = service.export_user_data(user_id)
        
        if "error" in export:
            return jsonify(export), 404
        
        # Return as downloadable JSON
        import json
        from datetime import datetime
        
        filename = f"user_data_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        response = make_response(json.dumps(export, indent=2, ensure_ascii=False))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Data export error")
        return jsonify({"error": "Internal server error"}), 500


# ============================================================================
# Biometric Data Deletion Endpoint
# ============================================================================

@consent_bp.route('/delete-biometric-data', methods=['POST'])
@jwt_required()
def delete_biometric_data():
    """
    Soft-delete all biometric data for a user.
    
    DPDP Compliance: Right to erasure (Section 12)
    
    Request Body:
        {
            "confirmation": "DELETE_MY_DATA" (exact match required)
        }
    
    Response:
        {
            "success": true,
            "status": "deleted",
            "deleted_at": "ISO8601",
            "records_affected": 3,
            "message": "Data scheduled for permanent deletion in 30 days"
        }
    
    Side Effects:
        - Soft-deletes all biometric templates
        - Revokes all consents
        - Invalidates all sessions
        - Creates audit log entry
    
    IRREVERSIBLE: User will need to re-enroll for biometric authentication.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        # Require exact confirmation string
        confirmation = data.get('confirmation')
        if confirmation != "DELETE_MY_DATA":
            return jsonify({
                "error": "Confirmation required",
                "message": "Include 'confirmation': 'DELETE_MY_DATA' to delete biometric data",
                "warning": "This action cannot be undone. You will need to re-enroll for biometric authentication."
            }), 400
        
        # Get user from JWT
        jwt_user_id = get_jwt_identity()
        user_id = parse_uuid(jwt_user_id, "jwt_user_id")
        
        # Delete data
        service = get_consent_service()
        count = service.soft_delete_biometric_data(
            user_id=user_id,
            ip_address=get_client_ip()
        )
        
        from datetime import datetime, timezone
        
        return jsonify({
            "success": True,
            "status": "deleted",
            "deleted_at": datetime.now(timezone.utc).isoformat(),
            "records_affected": count,
            "message": "Data scheduled for permanent deletion in 30 days. You will need to re-enroll for biometric authentication."
        }), 200
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Data deletion error")
        return jsonify({"error": "Internal server error"}), 500


# ============================================================================
# Consent Text Templates Endpoint
# ============================================================================

@consent_bp.route('/templates', methods=['GET'])
def get_consent_templates():
    """
    Get consent text templates for each purpose.
    
    These are the default consent texts that users will agree to.
    Customize for your specific use case and locale.
    
    Response:
        {
            "AUTHENTICATION": "...",
            "ACCESS_CONTROL": "...",
            "AUDIT": "..."
        }
    """
    return jsonify({
        "AUTHENTICATION": CONSENT_TEXT_AUTHENTICATION.strip(),
        "ACCESS_CONTROL": CONSENT_TEXT_ACCESS_CONTROL.strip(),
        "AUDIT": CONSENT_TEXT_AUDIT.strip(),
    }), 200


# ============================================================================
# Health Check
# ============================================================================

@consent_bp.route('/health', methods=['GET'])
def consent_health():
    """Health check for consent service."""
    try:
        from sqlalchemy import text
        db = get_db()
        db.execute(text("SELECT 1"))
        return jsonify({"status": "healthy", "service": "consent"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500
