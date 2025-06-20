package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// DBConfig 数据库配置
type DBConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// Connection 数据库连接
type Connection struct {
	*sql.DB
}

// NewConnection 创建新的数据库连接
func NewConnection(config DBConfig) (*Connection, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.User, config.Password, config.Host, config.Port, config.DBName)
	
	if config.SSLMode != "" {
		dsn = fmt.Sprintf("%s&tls=%s", dsn, config.SSLMode)
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %v", err)
	}

	// 设置连接池参数
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Minute * 5)

	// 测试连接
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	return &Connection{db}, nil
}

// Close 关闭数据库连接
func (c *Connection) Close() error {
	return c.DB.Close()
}

// Transaction 执行事务
func (c *Connection) Transaction(fn func(*sql.Tx) error) error {
	tx, err := c.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // 重新抛出panic
		}
	}()

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}
