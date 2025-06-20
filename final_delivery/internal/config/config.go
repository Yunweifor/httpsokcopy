package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config 表示应用程序的配置
type Config struct {
	// 服务器配置
	Server struct {
		Address     string `json:"address"`
		Port        int    `json:"port"`
		TLSEnabled  bool   `json:"tls_enabled"`
		TLSCertFile string `json:"tls_cert_file"`
		TLSKeyFile  string `json:"tls_key_file"`
	} `json:"server"`

	// 数据库配置
	Database struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		DBName   string `json:"dbname"`
		SSLMode  string `json:"sslmode"`
	} `json:"database"`

	// 日志配置
	LogLevel string `json:"log_level"`
	LogPath  string `json:"log_path"`

	// ACME配置
	ACME struct {
		DefaultCA         string `json:"default_ca"`
		DefaultEncryption string `json:"default_encryption"`
		RenewBeforeDays   int    `json:"renew_before_days"`
		ScriptPath        string `json:"script_path"`
	} `json:"acme"`

	// 告警配置
	Alert struct {
		DefaultExpiryAlertDays []int `json:"default_expiry_alert_days"`
	} `json:"alert"`
}

// Load 从配置文件加载配置
func Load() (*Config, error) {
	// 默认配置
	cfg := &Config{}
	cfg.Server.Address = "0.0.0.0"
	cfg.Server.Port = 8080
	cfg.Database.Host = "localhost"
	cfg.Database.Port = 3306
	cfg.Database.User = "root"
	cfg.Database.DBName = "httpsok"
	cfg.LogLevel = "info"
	cfg.LogPath = "logs"
	cfg.ACME.DefaultCA = "letsencrypt"
	cfg.ACME.DefaultEncryption = "ECC"
	cfg.ACME.RenewBeforeDays = 30
	cfg.ACME.ScriptPath = "/usr/local/bin/acme.sh"
	cfg.Alert.DefaultExpiryAlertDays = []int{30, 14, 7, 3, 1}

	// 尝试从配置文件加载
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "configs/config.json"
	}

	// 确保配置目录存在
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %v", err)
	}

	// 如果配置文件不存在，创建默认配置
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		defaultConfig, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal default config: %v", err)
		}
		if err := os.WriteFile(configPath, defaultConfig, 0644); err != nil {
			return nil, fmt.Errorf("failed to write default config: %v", err)
		}
	} else if err == nil {
		// 配置文件存在，读取配置
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %v", err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %v", err)
		}
	}

	// 从环境变量覆盖配置
	if host := os.Getenv("DB_HOST"); host != "" {
		cfg.Database.Host = host
	}
	if user := os.Getenv("DB_USER"); user != "" {
		cfg.Database.User = user
	}
	if password := os.Getenv("DB_PASSWORD"); password != "" {
		cfg.Database.Password = password
	}
	if dbname := os.Getenv("DB_NAME"); dbname != "" {
		cfg.Database.DBName = dbname
	}

	return cfg, nil
}
