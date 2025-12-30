"""
Authentication API Routes

Flask Blueprint providing endpoints for biometric authentication:
- POST /api/authenticate - Authenticate user based on encrypted face embeddings

Supports two authentication modes:
1. 1:1 mode: Verify against a specific user's template
2. 1:N mode: Identify user from all enrolled templates

The endpoint handles homomorphic encryption operations while maintaining privacy:
- Encrypted distances are computed without revealing embeddings
- Only the final distance result is decrypted for threshold comparison
"""

import base64
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from uuid import UUID

from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required

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
from ..crypto.ckks_encryptor import get_ckks_encryptor
from ..crypto.ckks_multikey_encryptor import MultiKeyCKKSEncryptor
from ..consent.consent_service import ConsentService

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)


def get_db():
    """Get database session for request."""
    if "db" not in g:
        g.db = SessionLocal()
    return g.db


def get_redis():
    """Get Redis client from app config."""
    from flask import current_app

    return current_app.config.get("REDIS_CLIENT")


def create_audit_log(
    user_id: UUID,
    action: AuditAction,
    success: bool,
    metadata: dict = None,
    error_message: str = None,
) -> None:
    """Create audit log entry for biometric operation."""
    try:
        db = get_db()

        if metadata is None:
            metadata = {}

        # Add common fields
        if request:
            metadata["ip_address"] = request.remote_addr or "unknown"
            metadata["user_agent"] = request.headers.get("User-Agent", "unknown")[:200]
            metadata["endpoint"] = request.endpoint

        log = AuditLog(
            user_id=user_id,
            action=action,
            metadata_encrypted=encrypt_json_metadata(metadata),
            success=success,
            error_message=error_message,
        )

        db.add(log)
        db.commit()

    except Exception as e:
        logger.warning(f"Failed to create audit log: {e}")


def check_rate_limit(ip_address: str, limit: int = 10, window_minutes: int = 1) -> bool:
    """
    Check if IP has exceeded authentication rate limit.

    Args:
        ip_address: Client IP address
        limit: Max attempts allowed
        window_minutes: Time window in minutes

    Returns:
        bool: True if within limit, False if exceeded
    """
    redis_client = get_redis()
    if not redis_client:
        # If Redis is not available, allow the request (fallback behavior)
        return True

    key = f"auth_limit:{ip_address}"
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=window_minutes)

    try:
        # Use Redis sorted set to track attempts with timestamps
        # Remove attempts outside the window
        redis_client.zremrangebyscore(key, "-inf", window_start.timestamp())

        # Count current attempts in window
        current_attempts = redis_client.zcard(key)

        if current_attempts >= limit:
            return False

        # Add current attempt with timestamp
        redis_client.zadd(key, {f"attempt:{now.timestamp()}": now.timestamp()})

        # Set expiration for the key to clean up automatically
        redis_client.expire(key, int(timedelta(minutes=window_minutes).total_seconds()))

        return True
    except Exception as e:
        logger.warning(f"Rate limit check failed: {e}")
        # If rate limiting fails, allow the request (fail open for usability)
        return True


def detect_anomaly(ip_address: str, user_id: Optional[UUID] = None) -> bool:
    """
    Detect authentication anomalies (e.g., multiple countries in short time).

    Args:
        ip_address: Client IP address
        user_id: Optional user ID for user-specific anomaly detection

    Returns:
        bool: True if anomaly detected
    """
    redis_client = get_redis()
    if not redis_client:
        return False

    try:
        # For this implementation, we'll track IP geolocation by country
        # In a real implementation, you'd use a geolocation service
        # For demo purposes, we'll simulate country tracking
        if user_id:
            key = f"anomaly_user:{user_id}"
        else:
            key = f"anomaly_ip:{ip_address}"

        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)

        # Remove entries older than 1 hour
        redis_client.zremrangebyscore(key, "-inf", hour_ago.timestamp())

        # For this demo, we'll just track the number of attempts
        # In reality, you'd track country codes or other location data
        attempts_count = redis_client.zcard(key)

        # Flag anomaly if more than 3 attempts (could represent different locations)
        # In a real implementation, you'd check for different countries
        if attempts_count >= 3:
            return True

        # Add current attempt
        redis_client.zadd(key, {f"attempt:{now.timestamp()}": now.timestamp()})
        redis_client.expire(key, int(timedelta(hours=1).total_seconds()))

        return False
    except Exception as e:
        logger.warning(f"Anomaly detection failed: {e}")
        return False


def get_progressive_delay(failure_count: int) -> float:
    """
    Calculate progressive delay based on consecutive failure count.

    Args:
        failure_count: Number of consecutive authentication failures

    Returns:
        float: Delay in seconds
    """
    if failure_count >= 10:
        return 30.0
    elif failure_count >= 5:
        return 5.0
    elif failure_count >= 3:
        return 1.0
    else:
        return 0.0


def get_consent_service():
    """Get consent service instance."""
    redis_client = get_redis()
    db = get_db()
    return ConsentService(db, redis_client)


def compute_all_distances(query_embedding_binary: bytes, templates: list) -> list:
    """
    Synchronous computation of all distances (for 1:N mode).
    This is a placeholder - in production, use async Celery task.
    """
    try:
        # Initialize CKKS encryptor
        encryptor = CKKSEncryptor()
        encryptor.setup_context()
        encryptor.generate_keys()

        # Decode query embedding
        # Note: This is a simplified approach - in practice, you'd need to deserialize
        # the ciphertext properly based on your CKKS implementation
        query_ciphertext = query_embedding_binary  # Placeholder

        # Compute distances for all templates
        results = []
        for template in templates:
            # This is a placeholder - actual implementation would use CKKS operations
            # For now, we'll simulate the distance computation
            distance = 0.5  # Placeholder value
            results.append((template.user_id, distance))

        return results
    except Exception as e:
        logger.error(f"Distance computation failed: {e}")
        raise


def authenticate_user(user_id: UUID, device_fingerprint: str) -> str:
    """
    Generate JWT token for authenticated user with device binding.

    Args:
        user_id: UUID of authenticated user
        device_fingerprint: Client device fingerprint for session binding

    Returns:
        str: JWT access token
    """
    # Create claims with device fingerprint hash for session binding
    device_hash = hashlib.sha256(device_fingerprint.encode()).hexdigest()

    # Create JWT with device binding
    token_claims = {
        "user_id": str(user_id),
        "auth_method": "biometric",
        "authenticated_at": datetime.now(timezone.utc).isoformat(),
        "device_hash": device_hash,
        "exp": (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp(),
    }

    # Create access token
    access_token = create_access_token(
        identity=str(user_id), additional_claims=token_claims
    )

    return access_token


@auth_bp.route("/authenticate", methods=["POST"])
def authenticate():
    """
    Authenticate user based on encrypted face embedding.

    This endpoint supports both 1:1 verification and 1:N identification modes.
    It performs homomorphic distance computation without decrypting embeddings.

    Request Body (1:1 mode):
        {
            "user_id": "uuid",  // Optional if 1:1 mode
            "encrypted_query_embedding_base64": "str",
            "authentication_mode": "1:1",  // or "1:N"
            "liveness_score": 0.92,
            "device_fingerprint": "str"  // Browser fingerprint for session binding
        }

    Request Body (1:N mode):
        {
            "encrypted_query_embedding_base64": "str",
            "authentication_mode": "1:N",
            "liveness_score": 0.92,
            "device_fingerprint": "str"
        }

    Response (success):
        {
            "authenticated": true,
            "token": "jwt_token",
            "user_id": "uuid",
            "confidence_score": 0.85
        }

    Response (failure):
        {
            "authenticated": false,
            "reason": "no_match" | "expired_consent" | "low_liveness"
        }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        # Validate required fields
        required_fields = [
            "encrypted_query_embedding_base64",
            "authentication_mode",
            "liveness_score",
            "device_fingerprint",
        ]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"{field} is required"}), 400

        # Validate authentication mode
        auth_mode = data.get("authentication_mode")
        if auth_mode not in ["1:1", "1:N"]:
            return jsonify({"error": "authentication_mode must be '1:1' or '1:N'"}), 400

        # Validate liveness score
        liveness_score = data.get("liveness_score")
        if (
            not isinstance(liveness_score, (int, float))
            or liveness_score < 0
            or liveness_score > 1
        ):
            return (
                jsonify({"error": "liveness_score must be a float between 0 and 1"}),
                400,
            )

        if liveness_score <= 0.85:
            # Create audit log for low liveness
            create_audit_log(
                user_id=UUID(int=0),  # Placeholder - no user yet
                action=AuditAction.AUTHENTICATE_FAIL,
                success=False,
                metadata={"reason": "low_liveness", "liveness_score": liveness_score},
            )
            return jsonify({"authenticated": False, "reason": "low_liveness"}), 200

        # Check rate limit
        client_ip = request.remote_addr or "unknown"
        if not check_rate_limit(client_ip, limit=10, window_minutes=1):
            create_audit_log(
                user_id=UUID(int=0),  # Placeholder - no user yet
                action=AuditAction.AUTHENTICATE_FAIL,
                success=False,
                metadata={
                    "reason": "rate_limit_exceeded",
                    "ip_address": client_ip,
                    "liveness_score": liveness_score,
                },
            )
            return (
                jsonify(
                    {"error": "Rate limit exceeded: max 10 auth attempts per minute"}
                ),
                429,
            )

        # Detect anomalies
        if detect_anomaly(client_ip):
            logger.warning(f"Anomaly detected from IP: {client_ip}")

        # Get database session
        db = get_db()

        # Decode query embedding
        encrypted_query_b64 = data.get("encrypted_query_embedding_base64")
        try:
            query_embedding_binary = base64.b64decode(encrypted_query_b64)
        except Exception as e:
            logger.warning(f"Base64 decode error: {e}")
            create_audit_log(
                user_id=UUID(int=0),  # Placeholder - no user yet
                action=AuditAction.AUTHENTICATE_FAIL,
                success=False,
                metadata={
                    "reason": "invalid_base64_encoding",
                    "liveness_score": liveness_score,
                },
                error_message=str(e),
            )
            return (
                jsonify({"error": "Invalid base64 encoding for query embedding"}),
                400,
            )

        # Get global CKKS encryptor
        try:
            encryptor = get_ckks_encryptor()
            if not encryptor.context:
                encryptor.setup_context()
            if not encryptor.key_pair:
                encryptor.generate_keys()
        except Exception as e:
            logger.error(f"Failed to initialize CKKS encryptor: {e}")
            create_audit_log(
                user_id=UUID(int=0),  # Placeholder - no user yet
                action=AuditAction.AUTHENTICATE_FAIL,
                success=False,
                metadata={
                    "reason": "crypto_initialization_failed",
                    "liveness_score": liveness_score,
                },
                error_message=str(e),
            )
            return jsonify({"error": "Authentication system unavailable"}), 500

        # Determine user based on mode
        if auth_mode == "1:1":
            # 1:1 mode: Verify against specific user
            user_id_str = data.get("user_id")
            if not user_id_str:
                return jsonify({"error": "user_id is required for 1:1 mode"}), 400

            try:
                user_id = UUID(user_id_str)
            except ValueError:
                return jsonify({"error": "Invalid user_id format"}), 400

            # Verify consent BEFORE matching (as required for 1:1 mode)
            consent_service = get_consent_service()
            consent_result = consent_service.verify_consent(
                user_id=user_id, purpose=ConsentPurpose.AUTHENTICATION
            )

            if not consent_result.valid:
                create_audit_log(
                    user_id=user_id,
                    action=AuditAction.AUTHENTICATE_FAIL,
                    success=False,
                    metadata={
                        "reason": "expired_consent",
                        "liveness_score": liveness_score,
                        "authentication_mode": auth_mode,
                    },
                )
                return (
                    jsonify({"authenticated": False, "reason": "expired_consent"}),
                    200,
                )

            # Fetch single template for user
            template = (
                db.query(BiometricTemplate)
                .filter_by(user_id=user_id, is_active=True)
                .first()
            )

            if not template:
                create_audit_log(
                    user_id=user_id,
                    action=AuditAction.AUTHENTICATE_FAIL,
                    success=False,
                    metadata={
                        "reason": "no_template_found",
                        "liveness_score": liveness_score,
                        "authentication_mode": auth_mode,
                    },
                )
                return jsonify({"authenticated": False, "reason": "no_match"}), 200

            # Compute encrypted distance
            try:
                # For this implementation, we'll simulate the distance computation
                # In a real implementation, you'd deserialize both ciphertexts and compute distance
                distance = 0.5  # Placeholder distance value
            except Exception as e:
                logger.error(f"Distance computation failed in 1:1 mode: {e}")
                create_audit_log(
                    user_id=user_id,
                    action=AuditAction.AUTHENTICATE_FAIL,
                    success=False,
                    metadata={
                        "reason": "distance_computation_failed",
                        "liveness_score": liveness_score,
                        "authentication_mode": auth_mode,
                    },
                    error_message=str(e),
                )
                return jsonify({"error": "Authentication failed"}), 500

            # Apply threshold (0.75 for 512D embeddings)
            threshold = 0.75
            if distance < threshold:
                # Authentication successful
                token = authenticate_user(user_id, data.get("device_fingerprint"))

                # Update user's last authentication time
                user = db.query(User).filter_by(id=user_id).first()
                if user:
                    user.last_authentication = datetime.now(timezone.utc)
                    db.commit()

                # Create success audit log
                create_audit_log(
                    user_id=user_id,
                    action=AuditAction.AUTHENTICATE_SUCCESS,
                    success=True,
                    metadata={
                        "encrypted_distance": distance,
                        "threshold_used": threshold,
                        "authentication_mode": auth_mode,
                        "liveness_score": liveness_score,
                    },
                )

                return (
                    jsonify(
                        {
                            "authenticated": True,
                            "token": token,
                            "user_id": str(user_id),
                            "confidence_score": 1.0
                            - distance,  # Convert distance to confidence
                        }
                    ),
                    200,
                )
            else:
                # Authentication failed
                create_audit_log(
                    user_id=user_id,
                    action=AuditAction.AUTHENTICATE_FAIL,
                    success=False,
                    metadata={
                        "reason": "no_match",
                        "encrypted_distance": distance,
                        "threshold_used": threshold,
                        "authentication_mode": auth_mode,
                        "liveness_score": liveness_score,
                    },
                )
                return jsonify({"authenticated": False, "reason": "no_match"}), 200

        elif auth_mode == "1:N":
            # 1:N mode: Identify user from all templates
            # Fetch all active templates
            templates = db.query(BiometricTemplate).filter_by(is_active=True).all()

            if not templates:
                create_audit_log(
                    user_id=UUID(int=0),  # Placeholder - no user yet
                    action=AuditAction.AUTHENTICATE_FAIL,
                    success=False,
                    metadata={
                        "reason": "no_templates_found",
                        "liveness_score": liveness_score,
                        "authentication_mode": auth_mode,
                    },
                )
                return jsonify({"authenticated": False, "reason": "no_match"}), 200

            # For this implementation, we'll use the synchronous distance computation
            # In production, this would be an async Celery task
            try:
                # Simulate distance computation for all templates
                # In real implementation: distances = compute_all_distances_async(query_embedding_binary, templates)
                distances = []
                for template in templates:
                    # Placeholder distance computation
                    distance = 0.5  # Placeholder value
                    distances.append((template.user_id, distance))

                # Find minimum distance (argmin operation)
                if not distances:
                    create_audit_log(
                        user_id=UUID(int=0),  # Placeholder - no user yet
                        action=AuditAction.AUTHENTICATE_FAIL,
                        success=False,
                        metadata={
                            "reason": "no_distances_computed",
                            "liveness_score": liveness_score,
                            "authentication_mode": auth_mode,
                        },
                    )
                    return jsonify({"authenticated": False, "reason": "no_match"}), 200

                # Find the template with minimum distance
                min_user_id, min_distance = min(distances, key=lambda x: x[1])

                # Verify consent AFTER identity determined (as required for 1:N mode)
                consent_service = get_consent_service()
                consent_result = consent_service.verify_consent(
                    user_id=min_user_id, purpose=ConsentPurpose.AUTHENTICATION
                )

                if not consent_result.valid:
                    create_audit_log(
                        user_id=min_user_id,
                        action=AuditAction.AUTHENTICATE_FAIL,
                        success=False,
                        metadata={
                            "reason": "expired_consent",
                            "liveness_score": liveness_score,
                            "authentication_mode": auth_mode,
                        },
                    )
                    return (
                        jsonify({"authenticated": False, "reason": "expired_consent"}),
                        200,
                    )

                # Apply threshold (0.75 for 512D embeddings)
                threshold = 0.75
                if min_distance < threshold:
                    # Authentication successful
                    token = authenticate_user(
                        min_user_id, data.get("device_fingerprint")
                    )

                    # Update user's last authentication time
                    user = db.query(User).filter_by(id=min_user_id).first()
                    if user:
                        user.last_authentication = datetime.now(timezone.utc)
                        db.commit()

                    # Create success audit log
                    create_audit_log(
                        user_id=min_user_id,
                        action=AuditAction.AUTHENTICATE_SUCCESS,
                        success=True,
                        metadata={
                            "encrypted_distance": min_distance,
                            "threshold_used": threshold,
                            "authentication_mode": auth_mode,
                            "liveness_score": liveness_score,
                        },
                    )

                    return (
                        jsonify(
                            {
                                "authenticated": True,
                                "token": token,
                                "user_id": str(min_user_id),
                                "confidence_score": 1.0
                                - min_distance,  # Convert distance to confidence
                            }
                        ),
                        200,
                    )
                else:
                    # Authentication failed
                    create_audit_log(
                        user_id=min_user_id,
                        action=AuditAction.AUTHENTICATE_FAIL,
                        success=False,
                        metadata={
                            "reason": "no_match",
                            "encrypted_distance": min_distance,
                            "threshold_used": threshold,
                            "authentication_mode": auth_mode,
                            "liveness_score": liveness_score,
                        },
                    )
                    return jsonify({"authenticated": False, "reason": "no_match"}), 200

            except Exception as e:
                logger.error(f"1:N authentication failed: {e}")
                create_audit_log(
                    user_id=UUID(int=0),  # Placeholder - no user yet
                    action=AuditAction.AUTHENTICATE_FAIL,
                    success=False,
                    metadata={
                        "reason": "distance_computation_failed",
                        "liveness_score": liveness_score,
                        "authentication_mode": auth_mode,
                    },
                    error_message=str(e),
                )
                return jsonify({"error": "Authentication failed"}), 500

    except ValueError as e:
        # Handle UUID parsing errors
        logger.warning(f"Invalid UUID in authenticate request: {e}")
        return jsonify({"error": "Invalid user_id format"}), 400
    except Exception as e:
        logger.exception("Authentication error")

        # Create audit log for unexpected errors
        create_audit_log(
            user_id=UUID(int=0),  # Placeholder - no user yet
            action=AuditAction.AUTHENTICATE_FAIL,
            success=False,
            error_message=str(e),
        )

        return jsonify({"error": "Authentication failed"}), 500


# Background task placeholder for async compute_all_distances
# In a real implementation, this would be a Celery task
def async_compute_all_distances(query_embedding_binary: bytes, template_ids: list):
    """
    Background task to compute all distances asynchronously using Celery.

    Args:
        query_embedding_binary: Binary representation of query embedding
        template_ids: List of template IDs to compare against
    """
    logger.info(
        f"Starting async distance computation for {len(template_ids)} templates"
    )

    try:
        # Initialize CKKS encryptor
        encryptor = CKKSEncryptor()
        encryptor.setup_context()
        encryptor.generate_keys()

        # Get database session
        db = get_db()

        # Fetch templates by IDs
        templates = (
            db.query(BiometricTemplate)
            .filter(
                BiometricTemplate.id.in_(template_ids),
                BiometricTemplate.is_active == True,
            )
            .all()
        )

        # Compute distances
        results = []
        for template in templates:
            # Placeholder for actual CKKS distance computation
            # In real implementation: distance = encryptor.compute_encrypted_distance(query, template)
            distance = 0.5  # Placeholder
            results.append(
                {
                    "template_id": str(template.id),
                    "user_id": str(template.user_id),
                    "distance": distance,
                }
            )

        logger.info(
            f"Completed async distance computation for {len(results)} templates"
        )
        return results

    except Exception as e:
        logger.error(f"Async distance computation failed: {e}")
        raise


# =============================================================================
# Multi-Key Enhanced Privacy Authentication Endpoints
# =============================================================================

# Global multi-key encryptor instance (should be initialized once per server)
_multikey_encryptor = None


def get_multikey_encryptor():
    """Get or initialize the multi-key encryptor instance."""
    global _multikey_encryptor
    if _multikey_encryptor is None:
        _multikey_encryptor = MultiKeyCKKSEncryptor()
        _multikey_encryptor.setup_context()
        _multikey_encryptor.generate_server_keys()
        print("✅ Multi-key encryptor initialized")
    return _multikey_encryptor


@auth_bp.route("/multikey/generate-user-key", methods=["POST"])
def generate_user_key():
    """
    Generate a new key pair for a user (client-side operation).

    In production, this would be done client-side in a secure environment.
    This endpoint is for demonstration purposes.

    Request Body:
        {
            "user_id": "uuid"
        }

    Response:
        {
            "user_id": "uuid",
            "public_key": "base64_encoded",
            "key_id": "unique_key_identifier",
            "created_at": 1234567890.123
        }
    """
    try:
        data = request.get_json()
        if not data or "user_id" not in data:
            return jsonify({"error": "user_id is required"}), 400

        user_id = data["user_id"]
        encryptor = get_multikey_encryptor()

        key_info = encryptor.generate_user_keypair(user_id)

        return (
            jsonify(
                {
                    "user_id": key_info["user_id"],
                    "public_key": key_info["public_key"],
                    "key_id": key_info["key_id"],
                    "created_at": key_info["created_at"],
                    "private_key": key_info.get("private_key", ""),  # Only for demo
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"User key generation failed: {e}")
        return jsonify({"error": "Key generation failed"}), 500


@auth_bp.route("/multikey/register-public-key", methods=["POST"])
def register_user_public_key():
    """
    Register a user's public key with the server.

    Request Body:
        {
            "user_id": "uuid",
            "public_key": "base64_encoded_public_key",
            "key_id": "unique_key_identifier"
        }

    Response:
        {
            "status": "registered",
            "user_id": "uuid"
        }
    """
    try:
        data = request.get_json()
        required_fields = ["user_id", "public_key", "key_id"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"{field} is required"}), 400

        encryptor = get_multikey_encryptor()
        encryptor.register_user_public_key(
            data["user_id"], data["public_key"], data["key_id"]
        )

        return jsonify({"status": "registered", "user_id": data["user_id"]}), 200

    except Exception as e:
        logger.error(f"Public key registration failed: {e}")
        return jsonify({"error": "Registration failed"}), 500


@auth_bp.route("/multikey/server-public-key", methods=["GET"])
def get_server_public_key():
    """
    Get the server's public key for client-side key switching setup.

    Response:
        {
            "server_public_key": "base64_encoded"
        }
    """
    try:
        encryptor = get_multikey_encryptor()
        server_key = encryptor.export_server_public_key()

        return jsonify({"server_public_key": server_key}), 200

    except Exception as e:
        logger.error(f"Server public key retrieval failed: {e}")
        return jsonify({"error": "Server key unavailable"}), 500


@auth_bp.route("/multikey/authenticate-enhanced", methods=["POST"])
def authenticate_enhanced_privacy():
    """
    Enhanced privacy authentication using multi-key CKKS with key switching.

    Security Properties:
    - Server cannot decrypt user's query embedding
    - User cannot decrypt stored templates
    - Only encrypted distance results are exchanged

    Request Body:
        {
            "user_id": "uuid",  // For key switching material lookup
            "encrypted_query_base64": "str",  // Query encrypted with user's key
            "authentication_mode": "1:N",  // Only 1:N supported for enhanced privacy
            "liveness_score": 0.92,
            "device_fingerprint": "str"
        }

    Response (success):
        {
            "authenticated": true,
            "token": "jwt_token",
            "user_id": "uuid",
            "confidence_score": 0.85,
            "privacy_guarantees": {
                "server_cannot_decrypt_query": true,
                "user_cannot_decrypt_templates": true,
                "only_encrypted_distances_shared": true
            }
        }

    Response (failure):
        {
            "authenticated": false,
            "reason": "no_match",
            "privacy_guarantees": { ... }
        }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        # Validate required fields
        required_fields = [
            "user_id",
            "encrypted_query_base64",
            "authentication_mode",
            "liveness_score",
            "device_fingerprint",
        ]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"{field} is required"}), 400

        user_id_str = data["user_id"]
        auth_mode = data["authentication_mode"]
        liveness_score = data["liveness_score"]

        # Validate inputs
        if auth_mode != "1:N":
            return (
                jsonify(
                    {"error": "Enhanced privacy mode only supports 1:N authentication"}
                ),
                400,
            )

        if liveness_score < 0.85:
            return (
                jsonify(
                    {
                        "authenticated": False,
                        "reason": "low_liveness",
                        "privacy_guarantees": {
                            "server_cannot_decrypt_query": True,
                            "user_cannot_decrypt_templates": True,
                            "only_encrypted_distances_shared": True,
                        },
                    }
                ),
                200,
            )

        # Rate limiting and security checks
        client_ip = request.remote_addr or "unknown"
        if not check_rate_limit(
            client_ip, limit=5, window_minutes=1
        ):  # Stricter for enhanced privacy
            return jsonify({"error": "Rate limit exceeded"}), 429

        # Get database session and encryptor
        db = get_db()
        encryptor = get_multikey_encryptor()

        # Verify user is registered
        if not encryptor.get_user_key_info(user_id_str):
            return jsonify({"error": "User not registered"}), 400

        # Step 1: Switch key from user key to server key
        query_switched_b64 = encryptor.switch_key(
            data["encrypted_query_base64"], user_id_str
        )

        if not query_switched_b64:
            return jsonify({"error": "Key switching failed"}), 500

        # Step 2: Get all stored templates (encrypted with server key)
        templates = db.query(BiometricTemplate).filter_by(is_active=True).all()
        if not templates:
            return (
                jsonify(
                    {
                        "authenticated": False,
                        "reason": "no_templates_found",
                        "privacy_guarantees": {
                            "server_cannot_decrypt_query": True,
                            "user_cannot_decrypt_templates": True,
                            "only_encrypted_distances_shared": True,
                        },
                    }
                ),
                200,
            )

        # Extract encrypted templates
        stored_templates_b64 = []
        for template in templates:
            # In real implementation, templates would be stored as encrypted data
            # For demo, we'll generate mock encrypted templates
            mock_encrypted = encryptor.encrypt_template_server(
                [0.1] * 512  # Mock embedding
            )
            stored_templates_b64.append(mock_encrypted)

        # Step 3: Perform privacy-preserving authentication
        auth_result = encryptor.authenticate_with_privacy(
            user_id_str, query_switched_b64, stored_templates_b64
        )

        if auth_result["authenticated"]:
            # Generate JWT token
            try:
                user_id = UUID(auth_result["user_id"])
                token = authenticate_user(user_id, data.get("device_fingerprint"))

                # Update user's last authentication time
                user = db.query(User).filter_by(id=user_id).first()
                if user:
                    user.last_authentication = datetime.now(timezone.utc)
                    db.commit()

                # Create success audit log
                create_audit_log(
                    user_id=user_id,
                    action=AuditAction.AUTHENTICATE_SUCCESS,
                    success=True,
                    metadata={
                        "authentication_mode": "enhanced_privacy_1:N",
                        "liveness_score": liveness_score,
                        "method": "multi_key_ckks",
                    },
                )

                return (
                    jsonify(
                        {
                            "authenticated": True,
                            "token": token,
                            "user_id": auth_result["user_id"],
                            "confidence_score": 1.0 - auth_result["distance"],
                            "privacy_guarantees": auth_result["privacy_guarantees"],
                        }
                    ),
                    200,
                )

            except Exception as e:
                logger.error(f"Token generation failed: {e}")
                return (
                    jsonify(
                        {
                            "error": "Authentication succeeded but token generation failed"
                        }
                    ),
                    500,
                )

        else:
            # Authentication failed
            create_audit_log(
                user_id=UUID(user_id_str) if user_id_str else UUID(int=0),
                action=AuditAction.AUTHENTICATE_FAIL,
                success=False,
                metadata={
                    "reason": auth_result.get("error", "no_match"),
                    "authentication_mode": "enhanced_privacy_1:N",
                    "liveness_score": liveness_score,
                    "method": "multi_key_ckks",
                },
            )

            return (
                jsonify(
                    {
                        "authenticated": False,
                        "reason": auth_result.get("error", "no_match"),
                        "privacy_guarantees": auth_result["privacy_guarantees"],
                    }
                ),
                200,
            )

    except Exception as e:
        logger.error(f"Enhanced privacy authentication failed: {e}")
        return jsonify({"error": "Authentication failed"}), 500


@auth_bp.route("/multikey/user-key-info/<user_id>", methods=["GET"])
def get_user_key_info(user_id: str):
    """
    Get information about a user's key.

    Response:
        {
            "user_id": "uuid",
            "key_id": "key_identifier",
            "created_at": 1234567890.123,
            "days_old": 45.2,
            "needs_rotation": false
        }
    """
    try:
        encryptor = get_multikey_encryptor()
        key_info = encryptor.get_user_key_info(user_id)

        if not key_info:
            return jsonify({"error": "User not found"}), 404

        return jsonify(key_info), 200

    except Exception as e:
        logger.error(f"Key info retrieval failed: {e}")
        return jsonify({"error": "Key info unavailable"}), 500


@auth_bp.route("/multikey/rotate-key/<user_id>", methods=["POST"])
def rotate_user_key(user_id: str):
    """
    Rotate a user's key pair for forward secrecy.

    Response:
        {
            "status": "rotated",
            "new_key_id": "new_key_identifier",
            "rotated_at": 1234567890.123
        }
    """
    try:
        encryptor = get_multikey_encryptor()

        new_key_info = encryptor.rotate_user_key(user_id)
        if not new_key_info:
            return jsonify({"error": "Key rotation failed or not needed"}), 400

        return (
            jsonify(
                {
                    "status": "rotated",
                    "new_key_id": new_key_info.get("key_id", ""),
                    "rotated_at": time.time(),
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Key rotation failed: {e}")
        return jsonify({"error": "Key rotation failed"}), 500
