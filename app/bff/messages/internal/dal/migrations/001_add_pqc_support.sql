-- Migration: Add PQC support to messages
-- Version: 001
-- Description: Adds PQC encryption support to message storage

-- Create PQC message containers table
CREATE TABLE IF NOT EXISTS pqc_message_containers (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    message_id BIGINT NOT NULL,
    auth_key_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    peer_id BIGINT NOT NULL,
    peer_type INT NOT NULL,
    
    -- Container data
    container_hash VARCHAR(64) NOT NULL UNIQUE,
    container_data LONGBLOB NOT NULL,
    
    -- PQC metadata
    algorithm VARCHAR(64) NOT NULL DEFAULT 'Kyber-1024+Dilithium-5',
    encryption_mode VARCHAR(32) NOT NULL DEFAULT 'PQC-Enhanced',
    pqc_version INT NOT NULL DEFAULT 1,
    
    -- Integrity verification
    signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    integrity_hash VARCHAR(64) NOT NULL,
    
    -- Performance tracking
    encryption_time_us BIGINT NOT NULL DEFAULT 0,
    decryption_time_us BIGINT NOT NULL DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    
    -- Indexes
    INDEX idx_message_id (message_id),
    INDEX idx_auth_key_id (auth_key_id),
    INDEX idx_user_peer (user_id, peer_id, peer_type),
    INDEX idx_container_hash (container_hash),
    INDEX idx_created_at (created_at),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create PQC message metadata table
CREATE TABLE IF NOT EXISTS pqc_message_metadata (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    message_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    peer_id BIGINT NOT NULL,
    peer_type INT NOT NULL,
    
    -- PQC encryption info
    is_pqc_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    pqc_algorithm VARCHAR(64) NOT NULL DEFAULT '',
    pqc_version INT NOT NULL DEFAULT 0,
    
    -- Signature info
    has_dilithium_sig BOOLEAN NOT NULL DEFAULT FALSE,
    signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    signature_public_key_hash VARCHAR(64) NOT NULL DEFAULT '',
    
    -- Performance metrics
    encryption_time_us BIGINT NOT NULL DEFAULT 0,
    decryption_time_us BIGINT NOT NULL DEFAULT 0,
    verification_time_us BIGINT NOT NULL DEFAULT 0,
    
    -- Hybrid mode info
    hybrid_mode BOOLEAN NOT NULL DEFAULT FALSE,
    classical_hash VARCHAR(64) NOT NULL DEFAULT '',
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes
    UNIQUE KEY uk_message_user_peer (message_id, user_id, peer_id, peer_type),
    INDEX idx_user_peer (user_id, peer_id, peer_type),
    INDEX idx_pqc_encrypted (is_pqc_encrypted),
    INDEX idx_pqc_algorithm (pqc_algorithm),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create PQC performance metrics table
CREATE TABLE IF NOT EXISTS pqc_performance_metrics (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    metric_date DATE NOT NULL,
    hour_bucket TINYINT NOT NULL DEFAULT 0, -- 0-23 for hourly buckets
    
    -- Operation counts
    total_messages BIGINT NOT NULL DEFAULT 0,
    pqc_encrypted_messages BIGINT NOT NULL DEFAULT 0,
    pqc_decrypted_messages BIGINT NOT NULL DEFAULT 0,
    integrity_verifications BIGINT NOT NULL DEFAULT 0,
    integrity_failures BIGINT NOT NULL DEFAULT 0,
    
    -- Performance metrics (in microseconds)
    avg_encryption_time_us BIGINT NOT NULL DEFAULT 0,
    max_encryption_time_us BIGINT NOT NULL DEFAULT 0,
    min_encryption_time_us BIGINT NOT NULL DEFAULT 0,
    
    avg_decryption_time_us BIGINT NOT NULL DEFAULT 0,
    max_decryption_time_us BIGINT NOT NULL DEFAULT 0,
    min_decryption_time_us BIGINT NOT NULL DEFAULT 0,
    
    avg_verification_time_us BIGINT NOT NULL DEFAULT 0,
    max_verification_time_us BIGINT NOT NULL DEFAULT 0,
    min_verification_time_us BIGINT NOT NULL DEFAULT 0,
    
    -- Success rates
    encryption_success_rate DECIMAL(5,4) NOT NULL DEFAULT 1.0000,
    decryption_success_rate DECIMAL(5,4) NOT NULL DEFAULT 1.0000,
    verification_success_rate DECIMAL(5,4) NOT NULL DEFAULT 1.0000,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes
    UNIQUE KEY uk_date_hour (metric_date, hour_bucket),
    INDEX idx_metric_date (metric_date),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create PQC key rotation log table
CREATE TABLE IF NOT EXISTS pqc_key_rotation_log (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    rotation_id VARCHAR(64) NOT NULL UNIQUE,
    
    -- Key information
    old_key_id VARCHAR(64) NOT NULL DEFAULT '',
    new_key_id VARCHAR(64) NOT NULL,
    key_algorithm VARCHAR(64) NOT NULL,
    
    -- Rotation details
    rotation_reason VARCHAR(128) NOT NULL,
    rotation_status ENUM('INITIATED', 'IN_PROGRESS', 'COMPLETED', 'FAILED') NOT NULL DEFAULT 'INITIATED',
    
    -- Affected data
    affected_messages BIGINT NOT NULL DEFAULT 0,
    migrated_messages BIGINT NOT NULL DEFAULT 0,
    failed_migrations BIGINT NOT NULL DEFAULT 0,
    
    -- Performance
    rotation_duration_ms BIGINT NOT NULL DEFAULT 0,
    
    -- Timestamps
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes
    INDEX idx_rotation_status (rotation_status),
    INDEX idx_started_at (started_at),
    INDEX idx_key_algorithm (key_algorithm)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add PQC columns to existing messages table (if it exists)
-- Note: This is conditional and should be adapted based on existing schema

-- Add PQC support columns to messages table
ALTER TABLE messages 
ADD COLUMN IF NOT EXISTS is_pqc_encrypted BOOLEAN NOT NULL DEFAULT FALSE AFTER message,
ADD COLUMN IF NOT EXISTS pqc_container_hash VARCHAR(64) NULL AFTER is_pqc_encrypted,
ADD COLUMN IF NOT EXISTS pqc_algorithm VARCHAR(64) NULL AFTER pqc_container_hash,
ADD COLUMN IF NOT EXISTS pqc_version INT NULL AFTER pqc_algorithm;

-- Add indexes for PQC columns
CREATE INDEX IF NOT EXISTS idx_messages_pqc_encrypted ON messages (is_pqc_encrypted);
CREATE INDEX IF NOT EXISTS idx_messages_pqc_container ON messages (pqc_container_hash);
CREATE INDEX IF NOT EXISTS idx_messages_pqc_algorithm ON messages (pqc_algorithm);

-- Create view for PQC message statistics
CREATE OR REPLACE VIEW pqc_message_stats AS
SELECT 
    DATE(created_at) as date,
    COUNT(*) as total_messages,
    SUM(CASE WHEN is_pqc_encrypted = TRUE THEN 1 ELSE 0 END) as pqc_messages,
    SUM(CASE WHEN is_pqc_encrypted = FALSE THEN 1 ELSE 0 END) as classical_messages,
    ROUND(
        (SUM(CASE WHEN is_pqc_encrypted = TRUE THEN 1 ELSE 0 END) * 100.0) / COUNT(*), 
        2
    ) as pqc_adoption_rate
FROM messages 
WHERE created_at >= DATE_SUB(CURRENT_DATE, INTERVAL 30 DAY)
GROUP BY DATE(created_at)
ORDER BY date DESC;

-- Create view for PQC performance summary
CREATE OR REPLACE VIEW pqc_performance_summary AS
SELECT 
    metric_date,
    SUM(total_messages) as daily_total_messages,
    SUM(pqc_encrypted_messages) as daily_pqc_messages,
    SUM(pqc_decrypted_messages) as daily_decrypted_messages,
    SUM(integrity_verifications) as daily_verifications,
    SUM(integrity_failures) as daily_failures,
    ROUND(AVG(avg_encryption_time_us), 2) as avg_encryption_time_us,
    ROUND(AVG(avg_decryption_time_us), 2) as avg_decryption_time_us,
    ROUND(AVG(avg_verification_time_us), 2) as avg_verification_time_us,
    ROUND(AVG(encryption_success_rate), 4) as avg_encryption_success_rate,
    ROUND(AVG(decryption_success_rate), 4) as avg_decryption_success_rate,
    ROUND(AVG(verification_success_rate), 4) as avg_verification_success_rate
FROM pqc_performance_metrics 
WHERE metric_date >= DATE_SUB(CURRENT_DATE, INTERVAL 7 DAY)
GROUP BY metric_date
ORDER BY metric_date DESC;

-- Insert initial performance metrics record
INSERT IGNORE INTO pqc_performance_metrics (
    metric_date, 
    hour_bucket,
    total_messages,
    pqc_encrypted_messages,
    pqc_decrypted_messages,
    integrity_verifications,
    avg_encryption_time_us,
    avg_decryption_time_us,
    avg_verification_time_us,
    encryption_success_rate,
    decryption_success_rate,
    verification_success_rate
) VALUES (
    CURRENT_DATE,
    HOUR(CURRENT_TIME),
    0, 0, 0, 0,
    0, 0, 0,
    1.0000, 1.0000, 1.0000
);

-- Create stored procedure for PQC metrics update
DELIMITER //

CREATE OR REPLACE PROCEDURE UpdatePQCMetrics(
    IN p_encryption_time_us BIGINT,
    IN p_decryption_time_us BIGINT,
    IN p_verification_time_us BIGINT,
    IN p_is_encryption BOOLEAN,
    IN p_is_decryption BOOLEAN,
    IN p_verification_success BOOLEAN
)
BEGIN
    DECLARE current_date DATE DEFAULT CURRENT_DATE;
    DECLARE current_hour TINYINT DEFAULT HOUR(CURRENT_TIME);
    
    -- Insert or update metrics for current hour
    INSERT INTO pqc_performance_metrics (
        metric_date,
        hour_bucket,
        total_messages,
        pqc_encrypted_messages,
        pqc_decrypted_messages,
        integrity_verifications,
        integrity_failures,
        avg_encryption_time_us,
        avg_decryption_time_us,
        avg_verification_time_us
    ) VALUES (
        current_date,
        current_hour,
        1,
        CASE WHEN p_is_encryption THEN 1 ELSE 0 END,
        CASE WHEN p_is_decryption THEN 1 ELSE 0 END,
        1,
        CASE WHEN p_verification_success THEN 0 ELSE 1 END,
        CASE WHEN p_is_encryption THEN p_encryption_time_us ELSE 0 END,
        CASE WHEN p_is_decryption THEN p_decryption_time_us ELSE 0 END,
        p_verification_time_us
    ) ON DUPLICATE KEY UPDATE
        total_messages = total_messages + 1,
        pqc_encrypted_messages = pqc_encrypted_messages + CASE WHEN p_is_encryption THEN 1 ELSE 0 END,
        pqc_decrypted_messages = pqc_decrypted_messages + CASE WHEN p_is_decryption THEN 1 ELSE 0 END,
        integrity_verifications = integrity_verifications + 1,
        integrity_failures = integrity_failures + CASE WHEN p_verification_success THEN 0 ELSE 1 END,
        avg_encryption_time_us = CASE 
            WHEN p_is_encryption THEN (avg_encryption_time_us + p_encryption_time_us) / 2 
            ELSE avg_encryption_time_us 
        END,
        avg_decryption_time_us = CASE 
            WHEN p_is_decryption THEN (avg_decryption_time_us + p_decryption_time_us) / 2 
            ELSE avg_decryption_time_us 
        END,
        avg_verification_time_us = (avg_verification_time_us + p_verification_time_us) / 2,
        updated_at = CURRENT_TIMESTAMP;
END //

DELIMITER ;

-- Grant necessary permissions (adjust as needed for your setup)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON pqc_message_containers TO 'teamgram_user'@'%';
-- GRANT SELECT, INSERT, UPDATE, DELETE ON pqc_message_metadata TO 'teamgram_user'@'%';
-- GRANT SELECT, INSERT, UPDATE ON pqc_performance_metrics TO 'teamgram_user'@'%';
-- GRANT SELECT, INSERT, UPDATE ON pqc_key_rotation_log TO 'teamgram_user'@'%';
-- GRANT EXECUTE ON PROCEDURE UpdatePQCMetrics TO 'teamgram_user'@'%';
