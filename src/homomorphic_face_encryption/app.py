"""
Main Flask Application for Privacy-Preserving Facial Recognition System

This module creates and configures the Flask application with:
- JWT authentication
- Consent management API
- Biometric authentication API
- Redis integration for caching
- Database initialization

Usage:
    # Development
    poetry run python -m homomorphic_face_encryption.app

    # With Flask CLI
    FLASK_APP=src/homomorphic_face_encryption/app.py flask run

    # Production (with gunicorn)
    gunicorn "homomorphic_face_encryption.app:create_app()"
"""

import logging
import os
from datetime import timedelta

from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from .api.routes import api_bp
from .api.consent_routes import consent_bp
from .api.enrollment_routes import enrollment_bp
from .api.authentication_routes import auth_bp
from .api.consent_middleware import init_consent_middleware
from .api.security_middleware import init_security_middleware, SecurityConfig
from .database import create_tables, engine
from .database.encryption_utils import setup_pgcrypto


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
try:
    from dotenv import load_dotenv

    load_dotenv()
    logger.info("Environment variables loaded from .env file")
except ImportError:
    logger.warning("python-dotenv not installed, using system environment variables")


def create_app(config_override: dict = None) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config_override: Optional dictionary to override default configuration

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)

    # =========================================================================
    # Configuration
    # =========================================================================

    # Base configuration
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET", "jwt-secret-key")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

    # Database configuration
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"postgresql://{os.getenv('DB_USER', 'postgres')}:"
        f"{os.getenv('DB_PASSWORD', 'password')}@"
        f"{os.getenv('DB_HOST', 'localhost')}:"
        f"{os.getenv('DB_PORT', '5432')}/"
        f"{os.getenv('DB_NAME', 'face_db')}"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Redis configuration
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    app.config["REDIS_URL"] = redis_url

    # Encryption configuration
    app.config["DB_ENCRYPTION_KEY"] = os.getenv("DB_ENCRYPTION_KEY")

    # Apply overrides
    if config_override:
        app.config.update(config_override)

    # =========================================================================
    # Initialize JWT Manager
    # =========================================================================
    jwt = JWTManager(app)
    logger.info("JWT Manager initialized")

    # Redis Client
    redis_client = None
    try:
        import redis

        redis_client = redis.from_url(redis_url, decode_responses=True)
        redis_client.ping()
        logger.info(f"Redis connected: {redis_url}")
    except ImportError:
        logger.warning("Redis package not installed. Caching disabled.")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}. Caching disabled.")

    app.config["REDIS_CLIENT"] = redis_client

    # Initialize consent middleware
    init_consent_middleware(app, redis_client)

    # Initialize security middleware (must be after consent middleware)
    security_config = SecurityConfig(
        jwt_secret_key=os.getenv("JWT_SECRET_KEY", "dev-secret-key"),
        jwt_public_key=os.getenv("JWT_PUBLIC_KEY", ""),
        redis_url=redis_url,
        cors_origins=os.getenv("CORS_ORIGINS", "https://app.example.com").split(","),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        enable_2fa=os.getenv("ENABLE_2FA", "false").lower() == "true",
        enable_request_logging=os.getenv("ENABLE_REQUEST_LOGGING", "true").lower()
        == "true",
        enable_rate_limiting=os.getenv("ENABLE_RATE_LIMITING", "true").lower()
        == "true",
    )
    init_security_middleware(app)

    # =========================================================================
    # Register Blueprints
    # =========================================================================

    # Main API routes (health, auth, biometric)
    app.register_blueprint(api_bp, url_prefix="/api")

    # Consent management routes
    app.register_blueprint(consent_bp, url_prefix="/api/consent")

    # Enrollment routes
    app.register_blueprint(enrollment_bp, url_prefix="/api")

    # Authentication routes
    app.register_blueprint(auth_bp, url_prefix="/api")

    # =========================================================================
    # Database Setup
    # =========================================================================

    with app.app_context():
        try:
            # Setup pgcrypto extension
            setup_pgcrypto(engine)
            logger.info("pgcrypto extension ready")
        except Exception as e:
            logger.warning(f"Could not setup pgcrypto: {e}")

        try:
            # Create database tables
            create_tables()
            logger.info("Database tables created")
        except Exception as e:
            logger.error(f"Database setup failed: {e}")

    # =========================================================================
    # Error Handlers (now handled by security middleware)
    # =========================================================================

    # =========================================================================
    # Root Routes
    # =========================================================================

    @app.route("/")
    def index():
        """API root with documentation links."""
        return jsonify(
            {
                "service": "Privacy-Preserving Facial Recognition API",
                "version": "0.1.0",
                "endpoints": {
                    "health": "/api/health",
                    "auth": {"get_token": "POST /api/auth/token"},
                    "biometric": {
                        "register": "POST /api/register",
                        "enroll": "POST /api/enroll",
                        "authenticate": "POST /api/authenticate",
                        "verify": "POST /api/verify",
                        "templates": "GET /api/templates",
                    },
                    "consent": {
                        "grant": "POST /api/consent/grant",
                        "verify": "GET /api/consent/verify/{user_id}/{purpose}",
                        "revoke": "POST /api/consent/revoke",
                        "dashboard": "GET /api/consent/dashboard/{user_id}",
                        "export": "POST /api/consent/export-data",
                        "delete": "POST /api/consent/delete-biometric-data",
                        "templates": "GET /api/consent/templates",
                    },
                },
                "documentation": {
                    "dpdp_compliance": "India Digital Personal Data Protection Act 2023",
                    "encryption": "CKKS Homomorphic Encryption (128-bit security)",
                    "consent_required": "All biometric operations require explicit consent",
                },
            }
        )

    @app.route("/health")
    def root_health():
        """Root-level health check."""
        return jsonify({"status": "healthy", "service": "facial-recognition-api"})

    # =========================================================================
    # Development Utilities
    # =========================================================================

    if app.debug or os.getenv("FLASK_ENV") == "development":

        @app.route("/api/dev/reset-db", methods=["POST"])
        def reset_database():
            """
            Reset database (DEVELOPMENT ONLY).

            Drops and recreates all tables.
            """
            from .database import drop_tables, create_tables
            from .database.init_db import init_database

            try:
                drop_tables()
                init_database(drop_existing=False)
                return jsonify({"message": "Database reset complete"}), 200
            except Exception as e:
                return jsonify({"error": str(e)}), 500

    logger.info("Application created successfully")
    return app


def run_development_server():
    """Run the development server."""
    app = create_app()
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000)),
        debug=os.getenv("FLASK_DEBUG", "true").lower() == "true",
    )


if __name__ == "__main__":
    run_development_server()
