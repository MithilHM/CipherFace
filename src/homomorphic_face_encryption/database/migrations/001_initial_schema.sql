-- ============================================================================
-- Initial Database Schema Migration
-- Privacy-Preserving Facial Recognition System
-- ============================================================================
-- 
-- This migration creates the complete database schema for:
-- - User management with UUID primary keys
-- - CKKS-encrypted biometric template storage
-- - DPDP-compliant consent records
-- - Tamper-resistant audit logging
--
-- PostgreSQL 15+ required
-- pgcrypto extension required
--
-- Run with:
--   psql -U postgres -d face_db -f 001_initial_schema.sql
-- ============================================================================

-- Enable pgcrypto extension for encryption functions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- ENUM Types
-- ============================================================================

-- Consent purpose enumeration (DPDP purpose limitation)
DO $$ BEGIN
    CREATE TYPE consent_purpose AS ENUM (
        'AUTHENTICATION',   -- Biometric authentication
        'ACCESS_CONTROL',   -- Physical access control systems
        'AUDIT'             -- Security audit logging
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Audit action enumeration (comprehensive audit trail)
DO $$ BEGIN
    CREATE TYPE audit_action AS ENUM (
        'ENROLL',                   -- New biometric template registered
        'AUTHENTICATE_SUCCESS',     -- Successful authentication
        'AUTHENTICATE_FAIL',        -- Failed authentication attempt
        'CONSENT_GRANT',            -- User granted consent
        'CONSENT_REVOKE',           -- User revoked consent
        'DATA_DELETE',              -- User requested data deletion
        'DATA_EXPORT',              -- User exported their data
        'SESSION_INVALIDATE',       -- Sessions invalidated
        'KEY_ROTATION'              -- Encryption key rotation event
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Users Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    -- UUID primary key for distributed system compatibility
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Unique username for authentication
    username VARCHAR(255) NOT NULL UNIQUE,
    
    -- Bcrypt hashed password (for future JWT auth)
    password_hash VARCHAR(255),
    
    -- Timestamps with timezone awareness
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    last_authentication TIMESTAMPTZ,
    
    -- Consent version tracking
    consent_version INTEGER NOT NULL DEFAULT 1,
    
    -- Soft deletion flag (DPDP right to erasure)
    is_active BOOLEAN NOT NULL DEFAULT true
);

-- Indexes for users table
CREATE INDEX IF NOT EXISTS ix_users_username ON users (username);
CREATE INDEX IF NOT EXISTS ix_users_is_active ON users (is_active);
CREATE INDEX IF NOT EXISTS ix_users_created_at ON users (created_at);

COMMENT ON TABLE users IS 'User accounts with minimal data collection (DPDP compliance)';
COMMENT ON COLUMN users.id IS 'UUID primary key for distributed compatibility';
COMMENT ON COLUMN users.consent_version IS 'Version of consent text user agreed to';
COMMENT ON COLUMN users.is_active IS 'Soft deletion flag for right to erasure';

-- ============================================================================
-- Biometric Templates Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS biometric_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Foreign key to users (cascade delete)
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- CKKS encrypted embedding (~16KB binary blob)
    -- This is homomorphically encrypted, NOT pgcrypto encrypted
    encrypted_embedding BYTEA NOT NULL,
    
    -- Hash of CKKS parameters for compatibility checking
    -- Prevents mixing ciphertexts from different encryption contexts
    encryption_params_hash VARCHAR(64) NOT NULL,
    
    -- Template version for re-enrollment tracking
    template_version INTEGER NOT NULL DEFAULT 1,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    
    -- Soft deletion
    is_active BOOLEAN NOT NULL DEFAULT true
);

-- Indexes for biometric_templates
CREATE INDEX IF NOT EXISTS ix_biometric_templates_user_id 
    ON biometric_templates (user_id);
CREATE INDEX IF NOT EXISTS ix_biometric_templates_user_active 
    ON biometric_templates (user_id, is_active);

-- Index for efficient "active templates for user" queries
CREATE INDEX IF NOT EXISTS ix_template_active_user 
    ON biometric_templates (user_id) 
    WHERE is_active = true;

COMMENT ON TABLE biometric_templates IS 'CKKS homomorphically encrypted face embeddings';
COMMENT ON COLUMN biometric_templates.encrypted_embedding IS '512D face embedding encrypted with CKKS FHE (~16KB)';
COMMENT ON COLUMN biometric_templates.encryption_params_hash IS 'SHA-256 of CKKS params for compatibility';

-- ============================================================================
-- Consent Records Table (DPDP Act 2023 Compliance)
-- ============================================================================

CREATE TABLE IF NOT EXISTS consent_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Foreign key to users (cascade delete)
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Purpose of consent (DPDP purpose limitation)
    purpose consent_purpose NOT NULL,
    
    -- SHA-256 hash of consent text for tamper detection
    consent_text_hash VARCHAR(64) NOT NULL,
    
    -- Encrypted IP address (pseudonymization requirement)
    -- Encrypted using pgcrypto/Fernet at application layer
    ip_address_encrypted BYTEA,
    
    -- Consent lifecycle timestamps
    consent_granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    consent_expires_at TIMESTAMPTZ NOT NULL,
    
    -- Revocation tracking
    is_revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    
    -- Constraint: revoked records must have revoked_at timestamp
    CONSTRAINT ck_consent_revoked_timestamp 
        CHECK ((is_revoked = false) OR (revoked_at IS NOT NULL))
);

-- Indexes for consent_records
CREATE INDEX IF NOT EXISTS ix_consent_records_user_id 
    ON consent_records (user_id);
CREATE INDEX IF NOT EXISTS ix_consent_records_is_revoked 
    ON consent_records (is_revoked);
CREATE INDEX IF NOT EXISTS ix_consent_verification 
    ON consent_records (user_id, purpose, is_revoked);

-- Partial unique index: only one active consent per purpose per user
CREATE UNIQUE INDEX IF NOT EXISTS uq_consent_user_purpose_active
    ON consent_records (user_id, purpose) 
    WHERE is_revoked = false;

-- Efficient lookup for consent verification
CREATE INDEX IF NOT EXISTS ix_consent_active_lookup
    ON consent_records (user_id, purpose)
    WHERE is_revoked = false;

COMMENT ON TABLE consent_records IS 'DPDP-compliant consent records with purpose limitation';
COMMENT ON COLUMN consent_records.purpose IS 'Specific purpose for data processing';
COMMENT ON COLUMN consent_records.consent_text_hash IS 'SHA-256 hash for non-repudiation';
COMMENT ON COLUMN consent_records.ip_address_encrypted IS 'AES-256 encrypted IP for pseudonymization';

-- ============================================================================
-- Audit Logs Table (Tamper-Resistant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- User reference (NULL for system events)
    -- SET NULL on user delete to preserve audit trail
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Action type
    action audit_action NOT NULL,
    
    -- Encrypted JSON metadata (IP, user agent, etc.)
    metadata_encrypted BYTEA,
    
    -- Timestamp (indexed for range queries)
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Operation result
    success BOOLEAN NOT NULL DEFAULT true,
    
    -- Error message for failed operations
    error_message TEXT,
    
    -- Session ID for correlating related events
    session_id VARCHAR(64)
);

-- Indexes for audit_logs
CREATE INDEX IF NOT EXISTS ix_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS ix_audit_logs_timestamp ON audit_logs (timestamp);
CREATE INDEX IF NOT EXISTS ix_audit_user_timestamp ON audit_logs (user_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_audit_action_timestamp ON audit_logs (action, timestamp);

-- Date range queries for breach investigation
CREATE INDEX IF NOT EXISTS ix_audit_date_range ON audit_logs (timestamp DESC);

COMMENT ON TABLE audit_logs IS 'Immutable audit trail for DPDP compliance and breach investigation';
COMMENT ON COLUMN audit_logs.metadata_encrypted IS 'AES-256 encrypted JSON with sensitive details';
COMMENT ON COLUMN audit_logs.session_id IS 'For correlating related audit events';

-- ============================================================================
-- Functions and Triggers
-- ============================================================================

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at trigger to users table
DROP TRIGGER IF EXISTS trigger_update_users_updated_at ON users;
CREATE TRIGGER trigger_update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Apply updated_at trigger to biometric_templates table
DROP TRIGGER IF EXISTS trigger_update_biometric_templates_updated_at ON biometric_templates;
CREATE TRIGGER trigger_update_biometric_templates_updated_at
    BEFORE UPDATE ON biometric_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Audit Log Immutability (CRITICAL for DPDP Compliance)
-- ============================================================================

-- Function to prevent UPDATE operations on audit_logs
CREATE OR REPLACE FUNCTION prevent_audit_log_update()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'UPDATE operations on audit_logs are prohibited. Audit records are immutable for DPDP compliance.';
END;
$$ LANGUAGE plpgsql;

-- Apply immutability trigger to audit_logs
DROP TRIGGER IF EXISTS trigger_prevent_audit_update ON audit_logs;
CREATE TRIGGER trigger_prevent_audit_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_update();

-- ============================================================================
-- Rollback SQL (for testing/development)
-- ============================================================================
-- To rollback this migration, run:
--
-- DROP TRIGGER IF EXISTS trigger_prevent_audit_update ON audit_logs;
-- DROP TRIGGER IF EXISTS trigger_update_biometric_templates_updated_at ON biometric_templates;
-- DROP TRIGGER IF EXISTS trigger_update_users_updated_at ON users;
-- DROP FUNCTION IF EXISTS prevent_audit_log_update();
-- DROP FUNCTION IF EXISTS update_updated_at_column();
-- DROP TABLE IF EXISTS audit_logs CASCADE;
-- DROP TABLE IF EXISTS consent_records CASCADE;
-- DROP TABLE IF EXISTS biometric_templates CASCADE;
-- DROP TABLE IF EXISTS users CASCADE;
-- DROP TYPE IF EXISTS audit_action;
-- DROP TYPE IF EXISTS consent_purpose;
-- ============================================================================

-- Verify setup
DO $$
BEGIN
    RAISE NOTICE 'Migration 001_initial_schema.sql completed successfully';
    RAISE NOTICE 'Tables created: users, biometric_templates, consent_records, audit_logs';
    RAISE NOTICE 'ENUM types: consent_purpose, audit_action';
    RAISE NOTICE 'Triggers: updated_at auto-update, audit_log immutability';
END $$;
