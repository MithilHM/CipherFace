"""
Consent Middleware for Flask Routes

Provides decorators for enforcing consent requirements on API endpoints.
Uses Redis caching for <5ms consent verification latency.

Usage:
    from api.consent_middleware import consent_required
    from database import ConsentPurpose
    
    @app.route('/api/authenticate')
    @jwt_required()
    @consent_required(ConsentPurpose.AUTHENTICATION)
    def authenticate():
        # This route only executes if user has valid AUTHENTICATION consent
        pass

DPDP Compliance:
- Consent verification on every biometric operation
- Failed checks logged for audit trail
- Immediate enforcement (with cache invalidation)
"""

import functools
import logging
from typing import Optional, Callable, Any
from uuid import UUID

from flask import g, request, jsonify, current_app
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request

from ..database import (
    ConsentPurpose,
    AuditLog,
    AuditAction,
    SessionLocal,
    encrypt_json_metadata,
)
from ..consent.consent_service import ConsentService

logger = logging.getLogger(__name__)


def get_db():
    """Get or create database session for request."""
    if 'db' not in g:
        g.db = SessionLocal()
    return g.db


def get_redis():
    """Get Redis client from app config."""
    return current_app.config.get('REDIS_CLIENT')


def get_consent_service() -> ConsentService:
    """Get or create consent service for request."""
    if 'consent_service' not in g:
        g.consent_service = ConsentService(get_db(), get_redis())
    return g.consent_service


def log_failed_consent_check(
    user_id: UUID,
    purpose: ConsentPurpose,
    reason: str,
    ip_address: Optional[str] = None
) -> None:
    """
    Log failed consent check to audit trail.
    
    DPDP Compliance: All consent enforcement actions are logged.
    """
    try:
        db = get_db()
        
        audit_log = AuditLog(
            user_id=user_id,
            action=AuditAction.AUTHENTICATE_FAIL,
            metadata_encrypted=encrypt_json_metadata({
                "reason": f"consent_check_failed:{reason}",
                "required_purpose": purpose.value,
                "ip_address": ip_address,
                "endpoint": request.endpoint,
                "method": request.method
            }),
            success=False,
            error_message=f"Consent verification failed: {reason}"
        )
        
        db.add(audit_log)
        db.commit()
        
    except Exception as e:
        logger.warning(f"Failed to log consent check failure: {e}")


def consent_required(purpose: ConsentPurpose):
    """
    Decorator that requires valid consent before executing route.
    
    This is the primary consent enforcement mechanism. Apply to any
    route that requires user consent for the specified purpose.
    
    Args:
        purpose: The ConsentPurpose required for this route
    
    Returns:
        Decorated function that checks consent before execution
    
    Usage:
        @app.route('/api/biometric/enroll')
        @jwt_required()
        @consent_required(ConsentPurpose.AUTHENTICATION)
        def enroll_biometric():
            # Only executes if user has valid AUTHENTICATION consent
            pass
    
    Response on failure (403 Forbidden):
        {
            "error": "Consent required",
            "consent_status": "not_found | expired | revoked",
            "purpose": "AUTHENTICATION",
            "message": "Please grant consent before using this feature"
        }
    
    Performance:
        - With Redis cache: <5ms (80% cache hit expected)
        - Without cache: <50ms (database query)
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def decorated_function(*args, **kwargs) -> Any:
            # Get user ID from JWT
            try:
                user_id_str = get_jwt_identity()
                if not user_id_str:
                    return jsonify({
                        "error": "Authentication required",
                        "message": "Valid JWT token required"
                    }), 401
                
                user_id = UUID(user_id_str)
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid JWT identity: {e}")
                return jsonify({
                    "error": "Invalid authentication",
                    "message": "JWT token contains invalid user ID"
                }), 401
            
            # Verify consent
            service = get_consent_service()
            result = service.verify_consent(user_id, purpose)
            
            if not result.valid:
                # Log failed consent check
                client_ip = request.headers.get('X-Forwarded-For', 
                             request.headers.get('X-Real-IP', 
                             request.remote_addr))
                
                log_failed_consent_check(
                    user_id=user_id,
                    purpose=purpose,
                    reason=result.status,
                    ip_address=client_ip
                )
                
                # Return 403 Forbidden with details
                response = {
                    "error": "Consent required",
                    "consent_status": result.status,
                    "purpose": purpose.value,
                    "message": get_consent_message(result.status, purpose)
                }
                
                # Add expiration info if expired
                if result.status == "expired" and result.expires_at:
                    response["expired_at"] = result.expires_at.isoformat()
                
                return jsonify(response), 403
            
            # Consent valid - proceed to route handler
            # Store consent info in g for route access
            g.consent_id = result.consent_id
            g.consent_purpose = purpose
            g.consent_remaining_days = result.remaining_days
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def get_consent_message(status: str, purpose: ConsentPurpose) -> str:
    """Get user-friendly message for consent status."""
    messages = {
        "not_found": f"Please grant {purpose.value.lower()} consent before using this feature.",
        "expired": f"Your {purpose.value.lower()} consent has expired. Please renew to continue.",
        "revoked": f"Your {purpose.value.lower()} consent was revoked. Please grant consent again to continue.",
    }
    return messages.get(status, f"Valid {purpose.value.lower()} consent is required.")


def any_consent_required(*purposes: ConsentPurpose):
    """
    Decorator that requires ANY ONE of the specified consents.
    
    Useful when multiple consent types allow access to a feature.
    
    Usage:
        @app.route('/api/logs')
        @jwt_required()
        @any_consent_required(ConsentPurpose.AUTHENTICATION, ConsentPurpose.AUDIT)
        def view_logs():
            pass
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def decorated_function(*args, **kwargs) -> Any:
            try:
                user_id_str = get_jwt_identity()
                if not user_id_str:
                    return jsonify({"error": "Authentication required"}), 401
                
                user_id = UUID(user_id_str)
            except (ValueError, TypeError):
                return jsonify({"error": "Invalid authentication"}), 401
            
            service = get_consent_service()
            
            # Check each purpose
            for purpose in purposes:
                result = service.verify_consent(user_id, purpose)
                if result.valid:
                    g.consent_id = result.consent_id
                    g.consent_purpose = purpose
                    return f(*args, **kwargs)
            
            # No valid consent found
            return jsonify({
                "error": "Consent required",
                "message": f"One of the following consents is required: {[p.value for p in purposes]}",
                "consent_status": "not_found"
            }), 403
        
        return decorated_function
    return decorator


def all_consents_required(*purposes: ConsentPurpose):
    """
    Decorator that requires ALL specified consents.
    
    Usage:
        @app.route('/api/admin/export')
        @jwt_required()
        @all_consents_required(ConsentPurpose.AUTHENTICATION, ConsentPurpose.AUDIT)
        def admin_export():
            pass
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def decorated_function(*args, **kwargs) -> Any:
            try:
                user_id_str = get_jwt_identity()
                if not user_id_str:
                    return jsonify({"error": "Authentication required"}), 401
                
                user_id = UUID(user_id_str)
            except (ValueError, TypeError):
                return jsonify({"error": "Invalid authentication"}), 401
            
            service = get_consent_service()
            missing = []
            
            for purpose in purposes:
                result = service.verify_consent(user_id, purpose)
                if not result.valid:
                    missing.append(purpose.value)
            
            if missing:
                return jsonify({
                    "error": "Consent required",
                    "message": f"Missing consent for: {missing}",
                    "missing_consents": missing
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def consent_warning(purpose: ConsentPurpose, warning_days: int = 7):
    """
    Decorator that adds consent expiration warning to response.
    
    Adds X-Consent-Warning header if consent expires within warning_days.
    Useful for prompting users to renew consent before expiration.
    
    Usage:
        @app.route('/api/authenticate')
        @jwt_required()
        @consent_required(ConsentPurpose.AUTHENTICATION)
        @consent_warning(ConsentPurpose.AUTHENTICATION, warning_days=14)
        def authenticate():
            pass
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def decorated_function(*args, **kwargs) -> Any:
            response = f(*args, **kwargs)
            
            # Check remaining days from g (set by consent_required)
            remaining = getattr(g, 'consent_remaining_days', None)
            
            if remaining is not None and remaining <= warning_days:
                # Flask response might be tuple (data, status_code)
                if isinstance(response, tuple):
                    resp_obj = current_app.make_response(response)
                else:
                    resp_obj = response
                
                resp_obj.headers['X-Consent-Warning'] = (
                    f"Consent expires in {remaining} days. Please renew."
                )
                resp_obj.headers['X-Consent-Expires-Days'] = str(remaining)
                
                return resp_obj
            
            return response
        
        return decorated_function
    return decorator


# Convenience decorators for specific purposes

def authentication_consent_required(f: Callable) -> Callable:
    """Shorthand for @consent_required(ConsentPurpose.AUTHENTICATION)"""
    return consent_required(ConsentPurpose.AUTHENTICATION)(f)


def access_control_consent_required(f: Callable) -> Callable:
    """Shorthand for @consent_required(ConsentPurpose.ACCESS_CONTROL)"""
    return consent_required(ConsentPurpose.ACCESS_CONTROL)(f)


def audit_consent_required(f: Callable) -> Callable:
    """Shorthand for @consent_required(ConsentPurpose.AUDIT)"""
    return consent_required(ConsentPurpose.AUDIT)(f)


class ConsentMiddlewareConfig:
    """
    Configuration for consent middleware behavior.
    
    Usage:
        app.config['CONSENT_MIDDLEWARE'] = ConsentMiddlewareConfig(
            cache_enabled=True,
            log_failed_checks=True,
            strict_mode=False
        )
    """
    
    def __init__(
        self,
        cache_enabled: bool = True,
        log_failed_checks: bool = True,
        strict_mode: bool = False,
        warning_days: int = 7
    ):
        """
        Initialize middleware configuration.
        
        Args:
            cache_enabled: Use Redis cache for consent verification
            log_failed_checks: Log failed consent checks to audit log
            strict_mode: If True, any error in consent check blocks request
            warning_days: Days before expiration to show warning
        """
        self.cache_enabled = cache_enabled
        self.log_failed_checks = log_failed_checks
        self.strict_mode = strict_mode
        self.warning_days = warning_days


def init_consent_middleware(app, redis_client=None):
    """
    Initialize consent middleware for Flask app.
    
    Call this in your app factory to set up the middleware.
    
    Usage:
        app = Flask(__name__)
        redis_client = redis.Redis(host='localhost', port=6379)
        init_consent_middleware(app, redis_client)
    
    Args:
        app: Flask application instance
        redis_client: Redis client for caching
    """
    app.config['REDIS_CLIENT'] = redis_client
    
    # Default configuration
    if 'CONSENT_MIDDLEWARE' not in app.config:
        app.config['CONSENT_MIDDLEWARE'] = ConsentMiddlewareConfig()
    
    # Register teardown
    @app.teardown_appcontext
    def cleanup_consent_middleware(exception=None):
        db = g.pop('db', None)
        if db is not None:
            db.close()
        g.pop('consent_service', None)
    
    logger.info("Consent middleware initialized")
