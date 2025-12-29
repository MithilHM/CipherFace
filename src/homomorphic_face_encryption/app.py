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
from flask_jwt_extended import JWTManager

from .api.routes import api_bp
from .api.consent_routes import consent_bp
from .api.consent_middleware import init_consent_middleware
from .database import create_tables, engine
from .database.encryption_utils import setup_pgcrypto


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


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
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET', 'jwt-secret-key')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
    
    # Database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"postgresql://{os.getenv('DB_USER', 'postgres')}:"
        f"{os.getenv('DB_PASSWORD', 'password')}@"
        f"{os.getenv('DB_HOST', 'localhost')}:"
        f"{os.getenv('DB_PORT', '5432')}/"
        f"{os.getenv('DB_NAME', 'face_db')}"
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Redis configuration
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
    app.config['REDIS_URL'] = redis_url
    
    # Encryption configuration
    app.config['DB_ENCRYPTION_KEY'] = os.getenv('DB_ENCRYPTION_KEY')
    
    # CORS configuration (for frontend development)
    app.config['CORS_ORIGINS'] = os.getenv('CORS_ORIGINS', '*').split(',')
    
    # Apply overrides
    if config_override:
        app.config.update(config_override)
    
    # =========================================================================
    # Extensions Initialization
    # =========================================================================
    
    # JWT Authentication
    jwt = JWTManager(app)
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            "error": "Token has expired",
            "message": "Please log in again"
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            "error": "Invalid token",
            "message": str(error)
        }), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            "error": "Authorization required",
            "message": "Please provide a valid JWT token"
        }), 401
    
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
    
    app.config['REDIS_CLIENT'] = redis_client
    
    # Initialize consent middleware
    init_consent_middleware(app, redis_client)
    
    # =========================================================================
    # Register Blueprints
    # =========================================================================
    
    # Main API routes (health, auth, biometric)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Consent management routes
    app.register_blueprint(consent_bp, url_prefix='/api/consent')
    
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
    # Error Handlers
    # =========================================================================
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "error": "Not found",
            "message": "The requested resource was not found"
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            "error": "Internal server error",
            "message": "An unexpected error occurred"
        }), 500
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            "error": "Bad request",
            "message": str(error.description) if hasattr(error, 'description') else "Invalid request"
        }), 400
    
    # =========================================================================
    # Root Routes
    # =========================================================================
    
    @app.route('/')
    def index():
        """API root with documentation links."""
        return jsonify({
            "service": "Privacy-Preserving Facial Recognition API",
            "version": "0.1.0",
            "endpoints": {
                "health": "/api/health",
                "auth": {
                    "get_token": "POST /api/auth/token"
                },
                "biometric": {
                    "register": "POST /api/register",
                    "verify": "POST /api/verify",
                    "templates": "GET /api/templates"
                },
                "consent": {
                    "grant": "POST /api/consent/grant",
                    "verify": "GET /api/consent/verify/{user_id}/{purpose}",
                    "revoke": "POST /api/consent/revoke",
                    "dashboard": "GET /api/consent/dashboard/{user_id}",
                    "export": "POST /api/consent/export-data",
                    "delete": "POST /api/consent/delete-biometric-data",
                    "templates": "GET /api/consent/templates"
                }
            },
            "documentation": {
                "dpdp_compliance": "India Digital Personal Data Protection Act 2023",
                "encryption": "CKKS Homomorphic Encryption (128-bit security)",
                "consent_required": "All biometric operations require explicit consent"
            }
        })
    
    @app.route('/health')
    def root_health():
        """Root-level health check."""
        return jsonify({
            "status": "healthy",
            "service": "facial-recognition-api"
        })
    
    # =========================================================================
    # Development Utilities
    # =========================================================================
    
    if app.debug or os.getenv('FLASK_ENV') == 'development':
        @app.route('/api/dev/reset-db', methods=['POST'])
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
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_DEBUG', 'true').lower() == 'true'
    )


if __name__ == '__main__':
    run_development_server()
