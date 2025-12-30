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


@api_bp.route('/debug/jwt-test', methods=['GET'])
@jwt_required()
def test_jwt():
    """Debug endpoint to test JWT token validation."""
    from flask import current_app
    user_id = get_jwt_identity()
    return jsonify({
        "status": "JWT valid",
        "user_id": user_id,
        "jwt_secret_first_10": current_app.config.get("JWT_SECRET_KEY", "NOT SET")[:10]
    }), 200


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
        logger.info(f"Created JWT token for user {user.id}, token starts with: {access_token[:50]}...")
        
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
    Register a user's face embedding.
    
    REAL IMPLEMENTATION:
    1. Decode base64 image
    2. Detect face using MTCNN
    3. Extract 512D embedding using FaceNet
    4. Store embedding in database
    
    Request Body:
        {
            "image": "base64_encoded_image"
        }
    
    Response:
        {
            "message": "Face registered successfully",
            "template_id": "uuid",
            "face_detected": true,
            "embedding_size": 512
        }
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
        
        # ============================================================
        # REAL FACE PROCESSING
        # ============================================================
        
        from ..biometric.face_service import get_face_service
        import json
        
        face_service = get_face_service()
        
        # Process image: detect face and extract embedding
        success, result = face_service.process_image(image_data)
        
        if not success:
            create_audit_log(
                user_id=user_id,
                action=AuditAction.ENROLL,
                success=False,
                metadata={"error": result}
            )
            return jsonify({
                "error": result,
                "face_detected": False
            }), 400
        
        embedding = result  # numpy array of shape (512,)
        
        # Serialize embedding as JSON (storing as bytes)
        embedding_json = json.dumps(embedding.tolist())
        encrypted_data = embedding_json.encode('utf-8')
        
        # Get encryption parameters hash
        params_hash = generate_encryption_params_hash()
        
        # Deactivate old templates (optional: keep only latest)
        old_templates = db.query(BiometricTemplate).filter_by(
            user_id=user_id,
            is_active=True
        ).all()
        for old in old_templates:
            old.is_active = False
        
        # Create new biometric template
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
                "embedding_size": len(embedding),
                "embedding_norm": float(sum(x**2 for x in embedding.tolist())**0.5),
                "params_hash": params_hash
            }
        )
        
        # Update user's last authentication time
        user.last_authentication = datetime.now(timezone.utc)
        db.commit()
        
        logger.info(f"Face enrolled successfully: user={user_id}, template={template.id}")
        
        return jsonify({
            "message": "Face registered successfully",
            "template_id": str(template.id),
            "face_detected": True,
            "embedding_size": len(embedding),
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
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500



# ============================================================================
# Face Verification (Authentication)
# ============================================================================

@api_bp.route('/verify', methods=['POST'])
@jwt_required()
@consent_required(ConsentPurpose.AUTHENTICATION)
def verify_face():
    """
    Verify a face against stored embeddings.
    
    REAL IMPLEMENTATION:
    1. Decode base64 image
    2. Detect face using MTCNN
    3. Extract 512D embedding using FaceNet
    4. Compare with stored embeddings using Euclidean distance
    5. Return match result
    
    Request Body:
        {
            "image": "base64_encoded_image"
        }
    
    Response (match found):
        {
            "authenticated": true,
            "user_id": "uuid",
            "confidence": 0.95,
            "distance": 0.45
        }
    
    Response (no match):
        {
            "authenticated": false,
            "message": "Face does not match",
            "confidence": 0.25
        }
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
        
        # ============================================================
        # REAL FACE PROCESSING
        # ============================================================
        
        from ..biometric.face_service import get_face_service
        import json
        import numpy as np
        
        face_service = get_face_service()
        
        # Process input image: detect face and extract embedding
        success, result = face_service.process_image(image_data)
        
        if not success:
            create_audit_log(
                user_id=user_id,
                action=AuditAction.AUTHENTICATE_FAIL,
                success=False,
                metadata={"error": result, "reason": "face_detection_failed"}
            )
            return jsonify({
                "authenticated": False,
                "message": result,
                "face_detected": False
            }), 400
        
        query_embedding = result  # numpy array of shape (512,)
        
        # Compare with stored templates
        best_distance = float('inf')
        best_template_id = None
        
        for template in templates:
            try:
                # Deserialize stored embedding
                stored_embedding_list = json.loads(template.encrypted_embedding.decode('utf-8'))
                stored_embedding = np.array(stored_embedding_list, dtype=np.float32)
                
                # Compute distance
                distance, _ = face_service.compare_embeddings(query_embedding, stored_embedding)
                
                if distance < best_distance:
                    best_distance = distance
                    best_template_id = str(template.id)
                    
            except Exception as e:
                logger.warning(f"Error comparing template {template.id}: {e}")
                continue
        
        # Check if match found (threshold is 1.0)
        THRESHOLD = face_service.MATCH_THRESHOLD
        authenticated = best_distance < THRESHOLD
        
        # Convert distance to confidence (0-1 scale)
        confidence = max(0.0, min(1.0, 1.0 - (best_distance / (2 * THRESHOLD))))
        
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
                    "confidence": round(confidence, 4),
                    "distance": round(best_distance, 4),
                    "template_id": best_template_id,
                    "templates_compared": len(templates)
                }
            )
            
            logger.info(f"Authentication SUCCESS: user={user_id}, distance={best_distance:.4f}, confidence={confidence:.2%}")
            
            return jsonify({
                "authenticated": True,
                "user_id": str(user_id),
                "confidence": round(confidence, 4),
                "distance": round(best_distance, 4),
                "message": "Face verified successfully"
            }), 200
        else:
            create_audit_log(
                user_id=user_id,
                action=AuditAction.AUTHENTICATE_FAIL,
                success=False,
                metadata={
                    "reason": "no_match",
                    "best_distance": round(best_distance, 4),
                    "confidence": round(confidence, 4),
                    "threshold": THRESHOLD
                }
            )
            
            logger.info(f"Authentication FAILED: user={user_id}, distance={best_distance:.4f}, threshold={THRESHOLD}")
            
            return jsonify({
                "authenticated": False,
                "message": "Face does not match enrolled template",
                "confidence": round(confidence, 4),
                "distance": round(best_distance, 4)
            }), 401
        
    except Exception as e:
        logger.exception("Face verification error")
        create_audit_log(
            user_id=UUID(get_jwt_identity()),
            action=AuditAction.AUTHENTICATE_FAIL,
            success=False,
            error_message=str(e)
        )
        return jsonify({"error": f"Verification failed: {str(e)}"}), 500



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
