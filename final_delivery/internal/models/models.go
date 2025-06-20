package models

import (
	"database/sql"
	"time"
)

// User 用户模型
type User struct {
	ID           uint64         `json:"id"`
	Username     string         `json:"username"`
	Email        string         `json:"email"`
	PasswordHash string         `json:"-"`
	FullName     sql.NullString `json:"full_name,omitempty"`
	Phone        sql.NullString `json:"phone,omitempty"`
	Role         string         `json:"role"`
	Status       string         `json:"status"`
	LastLoginAt  sql.NullTime   `json:"last_login_at,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// Certificate 证书模型
type Certificate struct {
	ID             uint64         `json:"id"`
	DomainMain     string         `json:"domain_main"`
	DomainSANs     sql.NullString `json:"domain_sans,omitempty"`
	CAType         string         `json:"ca_type"`
	EncryptionType string         `json:"encryption_type"`
	Status         string         `json:"status"`
	ValidFrom      sql.NullTime   `json:"valid_from,omitempty"`
	ValidTo        sql.NullTime   `json:"valid_to,omitempty"`
	AutoRenew      bool           `json:"auto_renew"`
	RenewBeforeDays int           `json:"renew_before_days"`
	CertData       sql.NullString `json:"-"`
	KeyData        sql.NullString `json:"-"`
	ChainData      sql.NullString `json:"-"`
	Notes          sql.NullString `json:"notes,omitempty"`
	UserID         uint64         `json:"user_id"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// Server 服务器模型
type Server struct {
	ID          uint64         `json:"id"`
	Name        string         `json:"name"`
	Hostname    string         `json:"hostname"`
	IPAddress   string         `json:"ip_address"`
	ServerType  string         `json:"server_type"`
	OSType      string         `json:"os_type"`
	OSVersion   sql.NullString `json:"os_version,omitempty"`
	Version     sql.NullString `json:"version,omitempty"`
	Port        int            `json:"port"`
	AuthType    string         `json:"auth_type"`
	Username    string         `json:"username"`
	AuthData    sql.NullString `json:"-"`
	Status      string         `json:"status"`
	AutoDeploy  bool           `json:"auto_deploy"`
	LastCheckAt sql.NullTime   `json:"last_check_at,omitempty"`
	Notes       sql.NullString `json:"notes,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// Monitor 监控模型
type Monitor struct {
	ID           uint64         `json:"id"`
	Host         string         `json:"host"`
	Port         int            `json:"port"`
	IPType       string         `json:"ip_type"`
	IPAddress    sql.NullString `json:"ip_address,omitempty"`
	CertificateID sql.NullInt64  `json:"certificate_id,omitempty"`
	CheckInterval int            `json:"check_interval"`
	Enabled      bool           `json:"enabled"`
	LastStatus   string         `json:"last_status"`
	ValidDays    sql.NullInt32  `json:"valid_days,omitempty"`
	CertGrade    sql.NullString `json:"cert_grade,omitempty"`
	EncryptionType sql.NullString `json:"encryption_type,omitempty"`
	Notes        sql.NullString `json:"notes,omitempty"`
	LastCheckAt  sql.NullTime   `json:"last_check_at,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// DNSValidation DNS验证记录模型
type DNSValidation struct {
	ID            uint64    `json:"id"`
	CertificateID uint64    `json:"certificate_id"`
	HostRecord    string    `json:"host_record"`
	RecordType    string    `json:"record_type"`
	RecordValue   string    `json:"record_value"`
	Status        string    `json:"status"`
	VerifiedAt    sql.NullTime `json:"verified_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Deployment 证书部署模型
type Deployment struct {
	ID            uint64    `json:"id"`
	CertificateID uint64    `json:"certificate_id"`
	ServerID      uint64    `json:"server_id"`
	CertPath      string    `json:"cert_path"`
	KeyPath       string    `json:"key_path"`
	ChainPath     sql.NullString `json:"chain_path,omitempty"`
	ConfigPath    sql.NullString `json:"config_path,omitempty"`
	AutoDeploy    bool      `json:"auto_deploy"`
	ReloadService bool      `json:"reload_service"`
	Status        string    `json:"status"`
	LastDeployedAt sql.NullTime `json:"last_deployed_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Alert 告警记录模型
type Alert struct {
	ID         uint64    `json:"id"`
	RuleID     uint64    `json:"rule_id"`
	TargetType string    `json:"target_type"`
	TargetID   uint64    `json:"target_id"`
	Message    string    `json:"message"`
	Severity   string    `json:"severity"`
	Status     string    `json:"status"`
	ResolvedAt sql.NullTime `json:"resolved_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AlertRule 告警规则模型
type AlertRule struct {
	ID             uint64    `json:"id"`
	Name           string    `json:"name"`
	AlertType      string    `json:"alert_type"`
	ConditionType  string    `json:"condition_type"`
	ConditionValue string    `json:"condition_value"`
	Severity       string    `json:"severity"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// NotificationChannel 通知渠道模型
type NotificationChannel struct {
	ID          uint64    `json:"id"`
	Name        string    `json:"name"`
	ChannelType string    `json:"channel_type"`
	Config      string    `json:"config"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// APIToken API令牌模型
type APIToken struct {
	ID         uint64       `json:"id"`
	UserID     uint64       `json:"user_id"`
	Name       string       `json:"name"`
	TokenHash  string       `json:"-"`
	Scopes     sql.NullString `json:"scopes,omitempty"`
	ExpiresAt  sql.NullTime `json:"expires_at,omitempty"`
	LastUsedAt sql.NullTime `json:"last_used_at,omitempty"`
	CreatedAt  time.Time    `json:"created_at"`
	UpdatedAt  time.Time    `json:"updated_at"`
}

// AuditLog 审计日志模型
type AuditLog struct {
	ID           uint64       `json:"id"`
	UserID       sql.NullInt64 `json:"user_id,omitempty"`
	Action       string       `json:"action"`
	ResourceType string       `json:"resource_type"`
	ResourceID   sql.NullString `json:"resource_id,omitempty"`
	IPAddress    string       `json:"ip_address"`
	UserAgent    sql.NullString `json:"user_agent,omitempty"`
	Details      sql.NullString `json:"details,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
}

// Task 任务队列模型
type Task struct {
	ID          uint64       `json:"id"`
	TaskType    string       `json:"task_type"`
	Status      string       `json:"status"`
	Priority    int          `json:"priority"`
	Payload     string       `json:"payload"`
	Result      sql.NullString `json:"result,omitempty"`
	Error       sql.NullString `json:"error,omitempty"`
	ScheduledAt sql.NullTime `json:"scheduled_at,omitempty"`
	StartedAt   sql.NullTime `json:"started_at,omitempty"`
	CompletedAt sql.NullTime `json:"completed_at,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}
