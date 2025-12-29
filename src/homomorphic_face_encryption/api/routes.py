"""
Flask API Routes for the Privacy-Preserving Facial Recognition System

This module provides the core API endpoints for:
- Health check
- Face registration (enrollment)
- Face verification (authentication)
- Legacy consent management (deprecated - use consent_routes instead)

All biometric endpoints require:
1. JWT authentication
2. Valid consent for the operation (enforced by middleware)
"""

import logging
from datetime import datetime, timezone
from uuid import UUID

from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token

from ..database import (
    User,
    BiometricTemplate,
    AuditLog,
    ConsentPurpose,
    AuditAction,
    SessionLocal,
    encrypt_json_metadata,
    generate_encryption_params_hash,
)
from .consent_middleware import consent_required, consent_warning


logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__)


def get_db():
    """Get database session for request."""
    if 'db' not in g:
        g.db = SessionLocal()
    return g.db


@api_bp.teardown_app_request
def cleanup_db(exception=None):
    """Close database session after request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def get_client_ip() -> str:
    """Get client IP address from request."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr or "unknown"


def create_audit_log(
    user_id: UUID,
    action: AuditAction,
    success: bool,
    metadata: dict = None,
    error_message: str = None
) -> None:
    """Create audit log entry for biometric operation."""
    try:
        db = get_db()
        
        if metadata is None:
            metadata = {}
        
        # Add common fields
        metadata["ip_address"] = get_client_ip()
        metadata["user_agent"] = request.headers.get('User-Agent', 'unknown')[:200]
        metadata["endpoint"] = request.endpoint
        
        log = AuditLog(
            user_id=user_id,
            action=action,
            metadata_encrypted=encrypt_json_metadata(metadata),
            success=success,
            error_message=error_message
        )
        
        db.add(log)
        db.commit()
        
    except Exception as e:
        logger.warning(f"Failed to create audit log: {e}")


# ============================================================================
# Health Check
# ============================================================================

@api_bp.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint.
    
    Returns:
        {"status": "healthy"} with 200 OK
    """
    try:
        db = get_db()
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500


# ============================================================================
# Authentication Endpoint (Get JWT Token)
# ============================================================================

@api_bp.route('/auth/token', methods=['POST'])
def get_token():
    """
    Get JWT access token.
    
    For development/testing only. In production, use proper auth flow.
    
    Request Body:
        {
            "username": "string"
        }
    
    Response:
        {
            "access_token": "jwt_token",
            "user_id": "uuid"
        }
    """
    try:
        data = request.get_json()
        if not data or 'username' not in data:
            return jsonify({"error": "username required"}), 400
        
        db = get_db()
        user = db.query(User).filter_by(
            username=data['username'],
            is_active=True
        ).first()
        
        if not user:
            # Auto-create user for development
            user = User(username=data['username'])
            db.add(user)
            db.commit()
            logger.info(f"Created new user: {user.username}")
        
        # Create access token with user_id as identity
        access_token = create_access_token(identity=str(user.id))
        
        return jsonify({
            "access_token": access_token,
            "user_id": str(user.id),
            "username": user.username
        }), 200
        
    except Exception as e:
        logger.exception("Token generation error")
        return jsonify({"error": "Token generation failed"}), 500


# ============================================================================
# Face Registration (Enrollment)
# ============================================================================

@api_bp.route('/register', methods=['POST'])
@jwt_required()
@consent_required(ConsentPurpose.AUTHENTICATION)
@consent_warning(ConsentPurpose.AUTHENTICATION, warning_days=14)
def register_face():
    """
    Register a user's face embedding (encrypted).
    
    Requires AUTHENTICATION consent.
    
    Request Body:
        {
            "image": "base64_encoded_image"
        }
    
    Response:
        {
            "message": "Face registered successfully",
            "template_id": "uuid"
        }
    
    Flow:
        1. Verify consent (handled by middleware)
        2. Extract face from image (MTCNN)
        3. Generate embedding (FaceNet)
        4. Encrypt embedding (CKKS)
        5. Store encrypted template
        6. Create audit log
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        # Get user ID from JWT
        user_id_str = get_jwt_identity()
        user_id = UUID(user_id_str)
        
        # Check for image data
        image_data = data.get('image')
        if not image_data:
            return jsonify({"error": "image is required"}), 400
        
        db = get_db()
        
        # Verify user exists
        user = db.query(User).filter_by(id=user_id, is_active=True).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # TODO: Implement actual face processing
        # For now, create a placeholder template
        
        # Import crypto module (lazy import to avoid circular deps)
        try:
            from ..crypto.ckks_encryptor import CKKSEncryptor
            from ..biometric.embedding_extractor import EmbeddingExtractor
            
            # Initialize encryptor
            encryptor = CKKSEncryptor()
            encryptor.setup_context()
            encryptor.generate_keys()
            
            # For demo: generate random embedding
            import numpy as np
            demo_embedding = np.random.randn(512).astype(np.float32).tolist()
            
            # Encrypt embedding
            ciphertext = encryptor.encrypt_embedding(demo_embedding)
            
            # Serialize ciphertext (placeholder)
            encrypted_data = b"CKKS_ENCRYPTED_TEMPLATE_PLACEHOLDER_" + bytes(16000)
        except ImportError as e:
            logger.warning(f"Crypto module not available: {e}")
            # Fallback for testing
            import os
            encrypted_data = os.urandom(16 * 1024)
        
        # Get encryption parameters hash
        params_hash = generate_encryption_params_hash()
        
        # Create biometric template
        template = BiometricTemplate(
            user_id=user_id,
            encrypted_embedding=encrypted_data,
            encryption_params_hash=params_hash,
            is_active=True
        )
        
        db.add(template)
        db.commit()
        
        # Create audit log
        create_audit_log(
            user_id=user_id,
            action=AuditAction.ENROLL,
            success=True,
            metadata={
                "template_id": str(template.id),
                "template_size": len(encrypted_data),
                "params_hash": params_hash
            }
        )
        
        # Update user's last authentication time
        user.last_authentication = datetime.now(timezone.utc)
        db.commit()
        
        return jsonify({
            "message": "Face registered successfully",
            "template_id": str(template.id),
            "encryption_params_hash": params_hash
        }), 201
        
    except Exception as e:
        logger.exception("Face registration error")
        create_audit_log(
            user_id=UUID(get_jwt_identity()),
            action=AuditAction.ENROLL,
            success=False,
            error_message=str(e)
        )
        return jsonify({"error": "Registration failed"}), 500


# ============================================================================
# Face Verification (Authentication)
# ============================================================================

@api_bp.route('/verify', methods=['POST'])
@jwt_required()
@consent_required(ConsentPurpose.AUTHENTICATION)
def verify_face():
    """
    Verify a face against stored encrypted embeddings.
    
    Requires AUTHENTICATION consent.
    
    Request Body:
        {
            "image": "base64_encoded_image"
        }
    
    Response (match found):
        {
            "authenticated": true,
            "user_id": "uuid",
            "confidence": 0.95
        }
    
    Response (no match):
        {
            "authenticated": false,
            "message": "No match found"
        }
    
    Flow:
        1. Verify consent (handled by middleware)
        2. Extract face from image
        3. Generate embedding
        4. Encrypt query embedding
        5. Compute encrypted distance to stored templates
        6. Decrypt distances and find match
        7. Create audit log
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        user_id_str = get_jwt_identity()
        user_id = UUID(user_id_str)
        
        image_data = data.get('image')
        if not image_data:
            return jsonify({"error": "image is required"}), 400
        
        db = get_db()
        
        # Get user's active templates
        templates = db.query(BiometricTemplate).filter_by(
            user_id=user_id,
            is_active=True
        ).all()
        
        if not templates:
            create_audit_log(
                user_id=user_id,
                action=AuditAction.AUTHENTICATE_FAIL,
                success=False,
                metadata={"reason": "no_templates"}
            )
            return jsonify({
                "authenticated": False,
                "message": "No biometric templates found. Please register first."
            }), 404
        
        # TODO: Implement actual face verification with homomorphic comparison
        # For now, simulate successful authentication
        
        authenticated = True  # Placeholder
        confidence = 0.95  # Placeholder
        
        if authenticated:
            # Update last authentication time
            user = db.query(User).filter_by(id=user_id).first()
            if user:
                user.last_authentication = datetime.now(timezone.utc)
                db.commit()
            
            create_audit_log(
                user_id=user_id,
                action=AuditAction.AUTHENTICATE_SUCCESS,
                success=True,
                metadata={
                    "confidence": confidence,
                    "templates_compared": len(templates)
                }
            )
            
            return jsonify({
                "authenticated": True,
                "user_id": str(user_id),
                "confidence": confidence
            }), 200
        else:
            create_audit_log(
                user_id=user_id,
                action=AuditAction.AUTHENTICATE_FAIL,
                success=False,
                metadata={"reason": "no_match"}
            )
            
            return jsonify({
                "authenticated": False,
                "message": "Face verification failed"
            }), 401
        
    except Exception as e:
        logger.exception("Face verification error")
        create_audit_log(
            user_id=UUID(get_jwt_identity()),
            action=AuditAction.AUTHENTICATE_FAIL,
            success=False,
            error_message=str(e)
        )
        return jsonify({"error": "Verification failed"}), 500


# ============================================================================
# Get User Templates
# ============================================================================

@api_bp.route('/templates', methods=['GET'])
@jwt_required()
@consent_required(ConsentPurpose.AUTHENTICATION)
def get_templates():
    """
    Get list of user's biometric templates.
    
    Response:
        {
            "templates": [
                {
                    "id": "uuid",
                    "created_at": "ISO8601",
                    "is_active": true,
                    "encryption_params_hash": "abc123..."
                }
            ],
            "count": 1
        }
    """
    try:
        user_id = UUID(get_jwt_identity())
        db = get_db()
        
        templates = db.query(BiometricTemplate).filter_by(
            user_id=user_id
        ).order_by(BiometricTemplate.created_at.desc()).all()
        
        return jsonify({
            "templates": [
                {
                    "id": str(t.id),
                    "created_at": t.created_at.isoformat(),
                    "is_active": t.is_active,
                    "encryption_params_hash": t.encryption_params_hash,
                    "template_version": t.template_version
                }
                for t in templates
            ],
            "count": len(templates)
        }), 200
        
    except Exception as e:
        logger.exception("Get templates error")
        return jsonify({"error": "Failed to retrieve templates"}), 500


# ============================================================================
# Delete Template
# ============================================================================

@api_bp.route('/templates/<template_id>', methods=['DELETE'])
@jwt_required()
@consent_required(ConsentPurpose.AUTHENTICATION)
def delete_template(template_id: str):
    """
    Soft-delete a specific biometric template.
    
    Path Parameters:
        template_id: UUID of the template to delete
    
    Response:
        {
            "message": "Template deleted",
            "template_id": "uuid"
        }
    """
    try:
        user_id = UUID(get_jwt_identity())
        template_uuid = UUID(template_id)
        
        db = get_db()
        
        template = db.query(BiometricTemplate).filter_by(
            id=template_uuid,
            user_id=user_id
        ).first()
        
        if not template:
            return jsonify({"error": "Template not found"}), 404
        
        # Soft delete
        template.is_active = False
        db.commit()
        
        create_audit_log(
            user_id=user_id,
            action=AuditAction.DATA_DELETE,
            success=True,
            metadata={"template_id": str(template_id)}
        )
        
        return jsonify({
            "message": "Template deleted",
            "template_id": str(template_id)
        }), 200
        
    except ValueError:
        return jsonify({"error": "Invalid template_id format"}), 400
    except Exception as e:
        logger.exception("Delete template error")
        return jsonify({"error": "Failed to delete template"}), 500


# ============================================================================
# Legacy Consent Endpoint (Deprecated)
# ============================================================================

@api_bp.route('/consent', methods=['POST'])
@jwt_required()
def manage_consent_legacy():
    """
    DEPRECATED: Use /api/consent/grant and /api/consent/revoke instead.
    
    This endpoint is maintained for backward compatibility only.
    """
    return jsonify({
        "error": "This endpoint is deprecated",
        "message": "Please use /api/consent/grant and /api/consent/revoke endpoints",
        "documentation": "/api/consent/templates for consent text templates"
    }), 410  # Gone
