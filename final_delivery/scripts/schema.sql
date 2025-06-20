-- httpsok系统数据库结构
-- 基于Go+MySQL的httpsok系统复刻版

-- 创建数据库
CREATE DATABASE IF NOT EXISTS httpsok CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE httpsok;

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    phone VARCHAR(20),
    role ENUM('admin', 'user', 'viewer') NOT NULL DEFAULT 'user',
    status ENUM('active', 'inactive', 'suspended') NOT NULL DEFAULT 'active',
    last_login_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 服务器表
CREATE TABLE IF NOT EXISTS servers (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    server_type ENUM('nginx', 'apache', 'other') NOT NULL DEFAULT 'nginx',
    os_type VARCHAR(50) NOT NULL,
    os_version VARCHAR(50),
    version VARCHAR(20),
    port INT UNSIGNED DEFAULT 22,
    auth_type ENUM('password', 'key', 'token') NOT NULL DEFAULT 'password',
    username VARCHAR(50) NOT NULL,
    auth_data TEXT,
    status ENUM('normal', 'error', 'offline') NOT NULL DEFAULT 'normal',
    auto_deploy BOOLEAN NOT NULL DEFAULT FALSE,
    last_check_at TIMESTAMP NULL,
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_ip_address (ip_address),
    INDEX idx_status (status),
    INDEX idx_server_type (server_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 证书表
CREATE TABLE IF NOT EXISTS certificates (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain_main VARCHAR(255) NOT NULL,
    domain_sans TEXT,
    ca_type ENUM('letsencrypt', 'zerossl', 'google', 'other') NOT NULL DEFAULT 'letsencrypt',
    encryption_type ENUM('ECC', 'RSA') NOT NULL DEFAULT 'ECC',
    status ENUM('pending', 'issued', 'expired', 'revoked', 'error') NOT NULL DEFAULT 'pending',
    valid_from TIMESTAMP NULL,
    valid_to TIMESTAMP NULL,
    auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
    renew_before_days INT UNSIGNED NOT NULL DEFAULT 30,
    cert_data TEXT,
    key_data TEXT,
    chain_data TEXT,
    notes TEXT,
    user_id INT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_domain_main (domain_main),
    INDEX idx_status (status),
    INDEX idx_valid_to (valid_to),
    INDEX idx_user_id (user_id),
    CONSTRAINT fk_certificates_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- DNS验证记录表
CREATE TABLE IF NOT EXISTS dns_validations (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    certificate_id INT UNSIGNED NOT NULL,
    host_record VARCHAR(255) NOT NULL,
    record_type VARCHAR(10) NOT NULL DEFAULT 'CNAME',
    record_value TEXT NOT NULL,
    status ENUM('pending', 'verified', 'failed') NOT NULL DEFAULT 'pending',
    verified_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_certificate_id (certificate_id),
    INDEX idx_status (status),
    CONSTRAINT fk_dns_validations_certificate FOREIGN KEY (certificate_id) REFERENCES certificates (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 证书部署表
CREATE TABLE IF NOT EXISTS deployments (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    certificate_id INT UNSIGNED NOT NULL,
    server_id INT UNSIGNED NOT NULL,
    cert_path VARCHAR(255) NOT NULL,
    key_path VARCHAR(255) NOT NULL,
    chain_path VARCHAR(255),
    config_path VARCHAR(255),
    auto_deploy BOOLEAN NOT NULL DEFAULT TRUE,
    reload_service BOOLEAN NOT NULL DEFAULT TRUE,
    status ENUM('pending', 'deployed', 'failed') NOT NULL DEFAULT 'pending',
    last_deployed_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_certificate_id (certificate_id),
    INDEX idx_server_id (server_id),
    INDEX idx_status (status),
    CONSTRAINT fk_deployments_certificate FOREIGN KEY (certificate_id) REFERENCES certificates (id) ON DELETE CASCADE,
    CONSTRAINT fk_deployments_server FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE,
    UNIQUE KEY uk_cert_server (certificate_id, server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 证书监控表
CREATE TABLE IF NOT EXISTS monitors (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    host VARCHAR(255) NOT NULL,
    port INT UNSIGNED NOT NULL DEFAULT 443,
    ip_type ENUM('ipv4', 'ipv6', 'both') NOT NULL DEFAULT 'ipv4',
    ip_address VARCHAR(45),
    certificate_id INT UNSIGNED,
    check_interval INT UNSIGNED NOT NULL DEFAULT 24, -- 小时
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_status ENUM('normal', 'warning', 'error') NOT NULL DEFAULT 'normal',
    valid_days INT,
    cert_grade VARCHAR(10),
    encryption_type VARCHAR(10),
    notes TEXT,
    last_check_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_host (host),
    INDEX idx_status (last_status),
    INDEX idx_certificate_id (certificate_id),
    INDEX idx_enabled (enabled),
    CONSTRAINT fk_monitors_certificate FOREIGN KEY (certificate_id) REFERENCES certificates (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 告警规则表
CREATE TABLE IF NOT EXISTS alert_rules (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    alert_type ENUM('cert_expiry', 'server_offline', 'cert_error') NOT NULL,
    condition_type ENUM('days', 'status_change', 'threshold') NOT NULL,
    condition_value VARCHAR(50) NOT NULL,
    severity ENUM('info', 'warning', 'error', 'critical') NOT NULL DEFAULT 'warning',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_alert_type (alert_type),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 告警通知渠道表
CREATE TABLE IF NOT EXISTS notification_channels (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    channel_type ENUM('email', 'sms', 'webhook', 'slack', 'wechat') NOT NULL,
    config JSON NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_channel_type (channel_type),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 告警规则-通知渠道关联表
CREATE TABLE IF NOT EXISTS rule_channels (
    rule_id INT UNSIGNED NOT NULL,
    channel_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (rule_id, channel_id),
    CONSTRAINT fk_rule_channels_rule FOREIGN KEY (rule_id) REFERENCES alert_rules (id) ON DELETE CASCADE,
    CONSTRAINT fk_rule_channels_channel FOREIGN KEY (channel_id) REFERENCES notification_channels (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 告警记录表
CREATE TABLE IF NOT EXISTS alerts (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    rule_id INT UNSIGNED NOT NULL,
    target_type ENUM('certificate', 'server', 'monitor') NOT NULL,
    target_id INT UNSIGNED NOT NULL,
    message TEXT NOT NULL,
    severity ENUM('info', 'warning', 'error', 'critical') NOT NULL,
    status ENUM('active', 'acknowledged', 'resolved') NOT NULL DEFAULT 'active',
    resolved_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_rule_id (rule_id),
    INDEX idx_target (target_type, target_id),
    INDEX idx_status (status),
    INDEX idx_severity (severity),
    CONSTRAINT fk_alerts_rule FOREIGN KEY (rule_id) REFERENCES alert_rules (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- API令牌表
CREATE TABLE IF NOT EXISTS api_tokens (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    name VARCHAR(100) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    scopes TEXT,
    expires_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_token_hash (token_hash),
    CONSTRAINT fk_api_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 审计日志表
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(50),
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    details JSON,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_resource (resource_type, resource_id),
    INDEX idx_created_at (created_at),
    CONSTRAINT fk_audit_logs_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 系统设置表
CREATE TABLE IF NOT EXISTS settings (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    value TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_category_name (category, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 任务队列表
CREATE TABLE IF NOT EXISTS tasks (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    task_type VARCHAR(50) NOT NULL,
    status ENUM('pending', 'running', 'completed', 'failed', 'cancelled') NOT NULL DEFAULT 'pending',
    priority TINYINT NOT NULL DEFAULT 5,
    payload JSON NOT NULL,
    result JSON,
    error TEXT,
    scheduled_at TIMESTAMP NULL,
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_task_type (task_type),
    INDEX idx_status (status),
    INDEX idx_scheduled_at (scheduled_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 初始化管理员用户
INSERT INTO users (username, email, password_hash, full_name, role, status)
VALUES ('admin', 'admin@example.com', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'System Administrator', 'admin', 'active');

-- 初始化系统设置
INSERT INTO settings (category, name, value) VALUES 
('system', 'site_name', 'HTTPSOK'),
('system', 'site_url', 'https://example.com'),
('certificate', 'default_ca', 'letsencrypt'),
('certificate', 'default_encryption', 'ECC'),
('certificate', 'renew_before_days', '30'),
('alert', 'default_expiry_alert_days', '30,14,7,3,1');
