"""
API Module for Privacy-Preserving Facial Recognition System

This module provides Flask blueprints for:
- api_bp: Core biometric API (registration, verification)
- consent_bp: Consent management API (grant, verify, revoke)

Middleware:
- consent_required: Decorator to enforce consent on routes
- authentication_consent_required: Shorthand for AUTH consent

Usage:
    from homomorphic_face_encryption.api import (
        api_bp,
        consent_bp,
        consent_required,
    )
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(consent_bp, url_prefix='/api/consent')
    
    # Use consent middleware
    @app.route('/protected')
    @jwt_required()
    @consent_required(ConsentPurpose.AUTHENTICATION)
    def protected_route():
        pass
"""

from .routes import api_bp
from .consent_routes import consent_bp
from .consent_middleware import (
    consent_required,
    any_consent_required,
    all_consents_required,
    consent_warning,
    authentication_consent_required,
    access_control_consent_required,
    audit_consent_required,
    init_consent_middleware,
    ConsentMiddlewareConfig,
)

__all__ = [
    # Blueprints
    "api_bp",
    "consent_bp",
    
    # Middleware decorators
    "consent_required",
    "any_consent_required",
    "all_consents_required",
    "consent_warning",
    
    # Convenience decorators
    "authentication_consent_required",
    "access_control_consent_required",
    "audit_consent_required",
    
    # Initialization
    "init_consent_middleware",
    "ConsentMiddlewareConfig",
]
