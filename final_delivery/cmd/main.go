package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/httpsok/internal/config"
	"github.com/httpsok/internal/database"
	"github.com/httpsok/internal/logger"
	"github.com/httpsok/internal/server"
)

func main() {
	// 初始化配置
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// 初始化日志
	logger := logger.NewLogger(cfg.LogLevel, cfg.LogPath)
	logger.Info("Starting httpsok service...")

	// 初始化数据库连接
	db, err := database.NewConnection(cfg.Database)
	if err != nil {
		logger.Fatal("Failed to connect to database", err)
	}
	defer db.Close()
	logger.Info("Database connection established")

	// 初始化HTTP服务器
	srv := server.NewServer(cfg, logger, db)

	// 启动HTTP服务器
	go func() {
		logger.Infof("HTTP server starting on %s", cfg.Server.Address)
		if err := srv.Start(); err != nil {
			logger.Fatal("Failed to start server", err)
		}
	}()

	// 优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")
	if err := srv.Shutdown(); err != nil {
		logger.Error("Server shutdown error", err)
	}

	logger.Info("Server stopped")
}
