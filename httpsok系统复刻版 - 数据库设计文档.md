# httpsok系统复刻版 - 数据库设计文档

## 1. 数据库概述

本文档描述了基于MySQL的httpsok系统复刻版的数据库设计。数据库设计遵循第三范式(3NF)原则，确保数据完整性和一致性，同时考虑了系统的性能需求和扩展性。

### 1.1 设计原则

- 遵循数据库设计的第三范式
- 适当冗余以提高查询性能
- 合理使用索引优化查询
- 考虑数据安全性和完整性
- 支持系统的可扩展性需求

### 1.2 数据库环境

- **数据库系统**：MySQL 8.0+
- **字符集**：UTF-8 Unicode (utf8mb4)
- **排序规则**：utf8mb4_unicode_ci
- **存储引擎**：InnoDB

## 2. 数据库表设计

### 2.1 用户管理相关表

#### 2.1.1 users（用户表）

存储系统用户信息。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 用户ID |
| username | VARCHAR(50) | NOT NULL, UNIQUE | 用户名 |
| email | VARCHAR(100) | NOT NULL, UNIQUE | 电子邮箱 |
| password_hash | VARCHAR(255) | NOT NULL | 密码哈希值 |
| full_name | VARCHAR(100) | | 用户全名 |
| phone | VARCHAR(20) | | 电话号码 |
| role | ENUM('admin', 'user', 'api') | NOT NULL, DEFAULT 'user' | 用户角色 |
| status | ENUM('active', 'inactive', 'locked') | NOT NULL, DEFAULT 'active' | 用户状态 |
| last_login_at | DATETIME | | 最后登录时间 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- UNIQUE INDEX `idx_username` (`username`)
- UNIQUE INDEX `idx_email` (`email`)
- INDEX `idx_status` (`status`)

#### 2.1.2 api_keys（API密钥表）

存储用户的API访问密钥。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 密钥ID |
| user_id | BIGINT | NOT NULL, FOREIGN KEY | 关联的用户ID |
| key_name | VARCHAR(50) | NOT NULL | 密钥名称 |
| api_key | VARCHAR(64) | NOT NULL, UNIQUE | API密钥 |
| secret_hash | VARCHAR(255) | NOT NULL | 密钥哈希值 |
| status | ENUM('active', 'inactive', 'revoked') | NOT NULL, DEFAULT 'active' | 密钥状态 |
| expires_at | DATETIME | | 过期时间 |
| last_used_at | DATETIME | | 最后使用时间 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_api_keys_user` (`user_id`) REFERENCES `users` (`id`)
- UNIQUE INDEX `idx_api_key` (`api_key`)
- INDEX `idx_status` (`status`)

#### 2.1.3 user_tokens（用户令牌表）

存储用户的访问令牌和刷新令牌。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 令牌ID |
| user_id | BIGINT | NOT NULL, FOREIGN KEY | 关联的用户ID |
| token_type | ENUM('access', 'refresh') | NOT NULL | 令牌类型 |
| token_hash | VARCHAR(255) | NOT NULL | 令牌哈希值 |
| expires_at | DATETIME | NOT NULL | 过期时间 |
| client_ip | VARCHAR(45) | | 客户端IP |
| user_agent | VARCHAR(255) | | 用户代理 |
| is_revoked | BOOLEAN | NOT NULL, DEFAULT FALSE | 是否已撤销 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_user_tokens_user` (`user_id`) REFERENCES `users` (`id`)
- INDEX `idx_token_type_expires` (`token_type`, `expires_at`)
- INDEX `idx_is_revoked` (`is_revoked`)

### 2.2 服务器管理相关表

#### 2.2.1 servers（服务器表）

存储服务器信息。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 服务器ID |
| user_id | BIGINT | NOT NULL, FOREIGN KEY | 所属用户ID |
| name | VARCHAR(100) | | 服务器名称 |
| hostname | VARCHAR(255) | NOT NULL | 主机名或IP地址 |
| port | INT | NOT NULL, DEFAULT 22 | SSH端口 |
| server_type | ENUM('nginx', 'apache', 'other') | NOT NULL, DEFAULT 'nginx' | 服务器类型 |
| os_type | VARCHAR(50) | | 操作系统类型 |
| os_version | VARCHAR(50) | | 操作系统版本 |
| web_server_version | VARCHAR(50) | | Web服务器版本 |
| auth_type | ENUM('password', 'key', 'token') | NOT NULL, DEFAULT 'password' | 认证类型 |
| username | VARCHAR(50) | | SSH用户名 |
| password_encrypted | VARCHAR(255) | | 加密的密码 |
| private_key_encrypted | TEXT | | 加密的私钥 |
| token_encrypted | VARCHAR(255) | | 加密的令牌 |
| status | ENUM('active', 'inactive', 'error') | NOT NULL, DEFAULT 'active' | 服务器状态 |
| last_check_at | DATETIME | | 最后检查时间 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_servers_user` (`user_id`) REFERENCES `users` (`id`)
- INDEX `idx_hostname` (`hostname`)
- INDEX `idx_server_type` (`server_type`)
- INDEX `idx_status` (`status`)

#### 2.2.2 server_configs（服务器配置表）

存储服务器的配置信息。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 配置ID |
| server_id | BIGINT | NOT NULL, FOREIGN KEY | 关联的服务器ID |
| config_type | ENUM('nginx', 'apache', 'system') | NOT NULL | 配置类型 |
| config_path | VARCHAR(255) | NOT NULL | 配置文件路径 |
| config_content | TEXT | | 配置文件内容 |
| is_active | BOOLEAN | NOT NULL, DEFAULT TRUE | 是否激活 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_server_configs_server` (`server_id`) REFERENCES `servers` (`id`)
- INDEX `idx_config_type` (`config_type`)
- INDEX `idx_is_active` (`is_active`)

#### 2.2.3 server_groups（服务器组表）

存储服务器分组信息。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 组ID |
| user_id | BIGINT | NOT NULL, FOREIGN KEY | 所属用户ID |
| name | VARCHAR(100) | NOT NULL | 组名称 |
| description | VARCHAR(255) | | 组描述 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_server_groups_user` (`user_id`) REFERENCES `users` (`id`)
- INDEX `idx_name` (`name`)

#### 2.2.4 server_group_mappings（服务器组映射表）

存储服务器与组的多对多关系。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 映射ID |
| server_id | BIGINT | NOT NULL, FOREIGN KEY | 服务器ID |
| group_id | BIGINT | NOT NULL, FOREIGN KEY | 组ID |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_mappings_server` (`server_id`) REFERENCES `servers` (`id`)
- FOREIGN KEY `fk_mappings_group` (`group_id`) REFERENCES `server_groups` (`id`)
- UNIQUE INDEX `idx_server_group` (`server_id`, `group_id`)

### 2.3 证书管理相关表

#### 2.3.1 certificates（证书表）

存储SSL证书信息。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 证书ID |
| user_id | BIGINT | NOT NULL, FOREIGN KEY | 所属用户ID |
| name | VARCHAR(100) | | 证书名称 |
| domains | TEXT | NOT NULL | 域名列表（JSON格式） |
| main_domain | VARCHAR(255) | NOT NULL | 主域名 |
| issuer | VARCHAR(100) | | 证书颁发者 |
| certificate_type | ENUM('single', 'wildcard', 'multi-domain') | NOT NULL | 证书类型 |
| encryption_type | ENUM('RSA', 'ECC') | NOT NULL, DEFAULT 'RSA' | 加密类型 |
| status | ENUM('pending', 'issued', 'expired', 'revoked', 'error') | NOT NULL, DEFAULT 'pending' | 证书状态 |
| certificate_pem | TEXT | | 证书PEM内容 |
| private_key_encrypted | TEXT | | 加密的私钥 |
| chain_pem | TEXT | | 证书链PEM内容 |
| issued_at | DATETIME | | 颁发时间 |
| expires_at | DATETIME | | 过期时间 |
| auto_renew | BOOLEAN | NOT NULL, DEFAULT TRUE | 是否自动续期 |
| renew_before_days | INT | NOT NULL, DEFAULT 30 | 提前多少天续期 |
| last_renewal_at | DATETIME | | 最后续期时间 |
| notes | TEXT | | 备注 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_certificates_user` (`user_id`) REFERENCES `users` (`id`)
- INDEX `idx_main_domain` (`main_domain`)
- INDEX `idx_status` (`status`)
- INDEX `idx_expires_at` (`expires_at`)
- INDEX `idx_certificate_type` (`certificate_type`)

#### 2.3.2 certificate_deployments（证书部署表）

存储证书部署信息。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 部署ID |
| certificate_id | BIGINT | NOT NULL, FOREIGN KEY | 关联的证书ID |
| server_id | BIGINT | NOT NULL, FOREIGN KEY | 关联的服务器ID |
| deploy_path | VARCHAR(255) | NOT NULL | 部署路径 |
| config_path | VARCHAR(255) | | 配置文件路径 |
| status | ENUM('pending', 'deployed', 'failed') | NOT NULL, DEFAULT 'pending' | 部署状态 |
| auto_deploy | BOOLEAN | NOT NULL, DEFAULT TRUE | 是否自动部署 |
| last_deploy_at | DATETIME | | 最后部署时间 |
| error_message | TEXT | | 错误信息 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_deployments_certificate` (`certificate_id`) REFERENCES `certificates` (`id`)
- FOREIGN KEY `fk_deployments_server` (`server_id`) REFERENCES `servers` (`id`)
- INDEX `idx_status` (`status`)
- INDEX `idx_auto_deploy` (`auto_deploy`)
- UNIQUE INDEX `idx_cert_server` (`certificate_id`, `server_id`)

#### 2.3.3 dns_challenges（DNS挑战记录表）

存储证书申请过程中的DNS挑战记录。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 记录ID |
| certificate_id | BIGINT | NOT NULL, FOREIGN KEY | 关联的证书ID |
| domain | VARCHAR(255) | NOT NULL | 域名 |
| challenge_type | ENUM('dns-01', 'http-01') | NOT NULL, DEFAULT 'dns-01' | 挑战类型 |
| record_name | VARCHAR(255) | NOT NULL | 记录名称 |
| record_type | VARCHAR(10) | NOT NULL | 记录类型 |
| record_value | TEXT | NOT NULL | 记录值 |
| status | ENUM('pending', 'verified', 'failed') | NOT NULL, DEFAULT 'pending' | 验证状态 |
| verified_at | DATETIME | | 验证时间 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_dns_challenges_certificate` (`certificate_id`) REFERENCES `certificates` (`id`)
- INDEX `idx_domain` (`domain`)
- INDEX `idx_status` (`status`)

### 2.4 监控告警相关表

#### 2.4.1 monitors（监控表）

存储监控配置信息。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 监控ID |
| user_id | BIGINT | NOT NULL, FOREIGN KEY | 所属用户ID |
| name | VARCHAR(100) | NOT NULL | 监控名称 |
| monitor_type | ENUM('certificate', 'server', 'domain') | NOT NULL | 监控类型 |
| target_id | BIGINT | | 目标ID（证书ID或服务器ID） |
| domain | VARCHAR(255) | | 域名（当监控类型为domain时） |
| port | INT | DEFAULT 443 | 端口 |
| check_interval | INT | NOT NULL, DEFAULT 86400 | 检查间隔（秒） |
| is_active | BOOLEAN | NOT NULL, DEFAULT TRUE | 是否激活 |
| last_check_at | DATETIME | | 最后检查时间 |
| next_check_at | DATETIME | | 下次检查时间 |
| status | ENUM('ok', 'warning', 'error', 'unknown') | NOT NULL, DEFAULT 'unknown' | 监控状态 |
| status_message | TEXT | | 状态信息 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_monitors_user` (`user_id`) REFERENCES `users` (`id`)
- INDEX `idx_monitor_type` (`monitor_type`)
- INDEX `idx_target_id` (`target_id`)
- INDEX `idx_domain` (`domain`)
- INDEX `idx_is_active` (`is_active`)
- INDEX `idx_status` (`status`)
- INDEX `idx_next_check_at` (`next_check_at`)

#### 2.4.2 alerts（告警表）

存储告警规则配置。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 告警ID |
| user_id | BIGINT | NOT NULL, FOREIGN KEY | 所属用户ID |
| name | VARCHAR(100) | NOT NULL | 告警名称 |
| alert_type | ENUM('certificate_expiry', 'server_down', 'certificate_error') | NOT NULL | 告警类型 |
| monitor_id | BIGINT | FOREIGN KEY | 关联的监控ID |
| condition_type | ENUM('days_before', 'status_change', 'value_threshold') | NOT NULL | 条件类型 |
| condition_value | VARCHAR(50) | NOT NULL | 条件值 |
| severity | ENUM('info', 'warning', 'error', 'critical') | NOT NULL, DEFAULT 'warning' | 严重程度 |
| is_active | BOOLEAN | NOT NULL, DEFAULT TRUE | 是否激活 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_alerts_user` (`user_id`) REFERENCES `users` (`id`)
- FOREIGN KEY `fk_alerts_monitor` (`monitor_id`) REFERENCES `monitors` (`id`)
- INDEX `idx_alert_type` (`alert_type`)
- INDEX `idx_is_active` (`is_active`)

#### 2.4.3 alert_channels（告警通道表）

存储告警通知渠道配置。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 通道ID |
| user_id | BIGINT | NOT NULL, FOREIGN KEY | 所属用户ID |
| name | VARCHAR(100) | NOT NULL | 通道名称 |
| channel_type | ENUM('email', 'sms', 'webhook', 'wechat', 'slack') | NOT NULL | 通道类型 |
| config | JSON | NOT NULL | 通道配置（JSON格式） |
| is_active | BOOLEAN | NOT NULL, DEFAULT TRUE | 是否激活 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_alert_channels_user` (`user_id`) REFERENCES `users` (`id`)
- INDEX `idx_channel_type` (`channel_type`)
- INDEX `idx_is_active` (`is_active`)

#### 2.4.4 alert_channel_bindings（告警通道绑定表）

存储告警规则与通知渠道的多对多关系。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 绑定ID |
| alert_id | BIGINT | NOT NULL, FOREIGN KEY | 告警ID |
| channel_id | BIGINT | NOT NULL, FOREIGN KEY | 通道ID |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_bindings_alert` (`alert_id`) REFERENCES `alerts` (`id`)
- FOREIGN KEY `fk_bindings_channel` (`channel_id`) REFERENCES `alert_channels` (`id`)
- UNIQUE INDEX `idx_alert_channel` (`alert_id`, `channel_id`)

#### 2.4.5 alert_history（告警历史表）

存储告警触发历史记录。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 历史ID |
| alert_id | BIGINT | NOT NULL, FOREIGN KEY | 关联的告警ID |
| monitor_id | BIGINT | NOT NULL, FOREIGN KEY | 关联的监控ID |
| severity | ENUM('info', 'warning', 'error', 'critical') | NOT NULL | 严重程度 |
| message | TEXT | NOT NULL | 告警消息 |
| data | JSON | | 告警数据（JSON格式） |
| is_resolved | BOOLEAN | NOT NULL, DEFAULT FALSE | 是否已解决 |
| resolved_at | DATETIME | | 解决时间 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_history_alert` (`alert_id`) REFERENCES `alerts` (`id`)
- FOREIGN KEY `fk_history_monitor` (`monitor_id`) REFERENCES `monitors` (`id`)
- INDEX `idx_severity` (`severity`)
- INDEX `idx_is_resolved` (`is_resolved`)
- INDEX `idx_created_at` (`created_at`)

### 2.5 任务管理相关表

#### 2.5.1 tasks（任务表）

存储系统任务信息。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 任务ID |
| task_type | ENUM('certificate_issue', 'certificate_renew', 'certificate_deploy', 'server_check', 'monitor_check') | NOT NULL | 任务类型 |
| status | ENUM('pending', 'running', 'completed', 'failed', 'cancelled') | NOT NULL, DEFAULT 'pending' | 任务状态 |
| priority | INT | NOT NULL, DEFAULT 5 | 优先级（1-10，10为最高） |
| target_type | VARCHAR(50) | | 目标类型 |
| target_id | BIGINT | | 目标ID |
| params | JSON | | 任务参数（JSON格式） |
| result | JSON | | 任务结果（JSON格式） |
| error_message | TEXT | | 错误信息 |
| progress | INT | NOT NULL, DEFAULT 0 | 进度（0-100） |
| scheduled_at | DATETIME | NOT NULL | 计划执行时间 |
| started_at | DATETIME | | 开始执行时间 |
| completed_at | DATETIME | | 完成时间 |
| created_by | BIGINT | FOREIGN KEY | 创建者ID |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_tasks_user` (`created_by`) REFERENCES `users` (`id`)
- INDEX `idx_task_type` (`task_type`)
- INDEX `idx_status` (`status`)
- INDEX `idx_priority` (`priority`)
- INDEX `idx_target` (`target_type`, `target_id`)
- INDEX `idx_scheduled_at` (`scheduled_at`)

#### 2.5.2 task_logs（任务日志表）

存储任务执行日志。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 日志ID |
| task_id | BIGINT | NOT NULL, FOREIGN KEY | 关联的任务ID |
| log_level | ENUM('debug', 'info', 'warning', 'error') | NOT NULL, DEFAULT 'info' | 日志级别 |
| message | TEXT | NOT NULL | 日志消息 |
| data | JSON | | 日志数据（JSON格式） |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_task_logs_task` (`task_id`) REFERENCES `tasks` (`id`)
- INDEX `idx_log_level` (`log_level`)
- INDEX `idx_created_at` (`created_at`)

#### 2.5.3 scheduled_tasks（定时任务表）

存储定时任务配置。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 定时任务ID |
| name | VARCHAR(100) | NOT NULL | 任务名称 |
| task_type | ENUM('certificate_check', 'server_check', 'backup', 'cleanup') | NOT NULL | 任务类型 |
| cron_expression | VARCHAR(100) | NOT NULL | Cron表达式 |
| params | JSON | | 任务参数（JSON格式） |
| is_active | BOOLEAN | NOT NULL, DEFAULT TRUE | 是否激活 |
| last_run_at | DATETIME | | 最后运行时间 |
| next_run_at | DATETIME | | 下次运行时间 |
| created_by | BIGINT | FOREIGN KEY | 创建者ID |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_scheduled_tasks_user` (`created_by`) REFERENCES `users` (`id`)
- INDEX `idx_task_type` (`task_type`)
- INDEX `idx_is_active` (`is_active`)
- INDEX `idx_next_run_at` (`next_run_at`)

### 2.6 系统管理相关表

#### 2.6.1 settings（系统设置表）

存储系统全局设置。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 设置ID |
| setting_key | VARCHAR(100) | NOT NULL, UNIQUE | 设置键 |
| setting_value | TEXT | | 设置值 |
| setting_type | ENUM('string', 'number', 'boolean', 'json') | NOT NULL, DEFAULT 'string' | 设置类型 |
| description | VARCHAR(255) | | 设置描述 |
| is_system | BOOLEAN | NOT NULL, DEFAULT FALSE | 是否系统设置 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- UNIQUE INDEX `idx_setting_key` (`setting_key`)
- INDEX `idx_is_system` (`is_system`)

#### 2.6.2 user_settings（用户设置表）

存储用户个人设置。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 设置ID |
| user_id | BIGINT | NOT NULL, FOREIGN KEY | 用户ID |
| setting_key | VARCHAR(100) | NOT NULL | 设置键 |
| setting_value | TEXT | | 设置值 |
| setting_type | ENUM('string', 'number', 'boolean', 'json') | NOT NULL, DEFAULT 'string' | 设置类型 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | 更新时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_user_settings_user` (`user_id`) REFERENCES `users` (`id`)
- UNIQUE INDEX `idx_user_setting` (`user_id`, `setting_key`)

#### 2.6.3 audit_logs（审计日志表）

存储系统操作审计日志。

| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|-----|
| id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | 日志ID |
| user_id | BIGINT | FOREIGN KEY | 用户ID |
| action | VARCHAR(100) | NOT NULL | 操作类型 |
| resource_type | VARCHAR(50) | | 资源类型 |
| resource_id | BIGINT | | 资源ID |
| details | JSON | | 操作详情（JSON格式） |
| ip_address | VARCHAR(45) | | IP地址 |
| user_agent | VARCHAR(255) | | 用户代理 |
| created_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | 创建时间 |

索引：
- PRIMARY KEY (`id`)
- FOREIGN KEY `fk_audit_logs_user` (`user_id`) REFERENCES `users` (`id`)
- INDEX `idx_action` (`action`)
- INDEX `idx_resource` (`resource_type`, `resource_id`)
- INDEX `idx_created_at` (`created_at`)

## 3. 数据库关系图

```
+---------------+     +----------------+     +----------------+
|    users      |<----|  api_keys      |     |  user_tokens   |
+---------------+     +----------------+     +----------------+
       ^                                            ^
       |                                            |
       +--------------------------------------------+
       |
       v
+---------------+     +----------------+     +----------------+
|   servers     |<--->| server_configs |     | server_groups  |
+---------------+     +----------------+     +----------------+
       ^                                            ^
       |                                            |
       v                                            v
+---------------+     +----------------+     +----------------+
| certificates  |<--->| cert_deployments|<--->|server_group_map|
+---------------+     +----------------+     +----------------+
       ^
       |
       v
+---------------+     +----------------+     +----------------+
| dns_challenges|     |   monitors     |<--->|    alerts      |
+---------------+     +----------------+     +----------------+
                             ^                      ^
                             |                      |
                             v                      v
                      +----------------+     +----------------+
                      | alert_history  |<--->|alert_channels  |
                      +----------------+     +----------------+
                                                    ^
                                                    |
                                                    v
                                            +----------------+
                                            |channel_bindings|
                                            +----------------+
```

## 4. 数据库初始化

### 4.1 初始化脚本

创建数据库和表的SQL脚本将包含在项目的`/db/migrations`目录中，按照版本号命名，例如：

- `V1__create_base_tables.sql`
- `V2__add_certificate_tables.sql`
- `V3__add_monitor_tables.sql`

### 4.2 初始数据

系统初始化时需要插入的基础数据，包括：

- 默认管理员用户
- 系统设置
- 默认告警规则
- 默认监控配置

### 4.3 数据迁移策略

使用Flyway或类似工具管理数据库版本和迁移：

- 版本化的迁移脚本
- 自动执行迁移
- 迁移历史记录
- 回滚支持

## 5. 数据库优化

### 5.1 索引优化

- 为常用查询字段创建索引
- 为外键创建索引
- 为排序和过滤条件创建索引
- 定期分析和优化索引

### 5.2 查询优化

- 使用预编译语句
- 避免全表扫描
- 限制结果集大小
- 使用适当的连接类型

### 5.3 性能考量

- 使用连接池管理数据库连接
- 配置适当的缓存策略
- 定期维护和优化数据库
- 监控数据库性能指标

## 6. 数据安全

### 6.1 数据加密

- 敏感数据加密存储（密码、私钥等）
- 传输层加密（TLS）
- 加密密钥管理

### 6.2 访问控制

- 基于角色的访问控制
- 最小权限原则
- 数据库用户权限隔离

### 6.3 数据备份

- 定期全量备份
- 增量备份策略
- 备份验证和恢复测试

## 7. 扩展性考虑

### 7.1 分表策略

对于可能增长较快的表（如audit_logs、task_logs等），考虑按时间或ID范围分表。

### 7.2 读写分离

随着系统规模增长，可考虑实施主从复制和读写分离：

- 主库处理写操作
- 从库处理读操作
- 负载均衡

### 7.3 分库分表

对于超大规模部署，可考虑水平分片：

- 按用户ID分片
- 按时间分片
- 使用中间件管理分片
