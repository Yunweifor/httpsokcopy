package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/httpsok/internal/config"
	"github.com/httpsok/internal/controllers"
	"github.com/httpsok/internal/database"
	"github.com/httpsok/internal/logger"
	"github.com/httpsok/internal/middleware"
)

// Server HTTP服务器
type Server struct {
	router *gin.Engine
	server *http.Server
	logger logger.Logger
	config *config.Config
}

// NewServer 创建新的HTTP服务器
func NewServer(cfg *config.Config, log logger.Logger, db *database.Connection) *Server {
	// 设置Gin模式
	if cfg.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	
	// 使用自定义日志中间件
	router.Use(middleware.Logger(log))
	router.Use(middleware.Recovery(log))
	
	// 创建控制器
	userController := controllers.NewUserController(db, log)
	certController := controllers.NewCertificateController(db, log)
	serverController := controllers.NewServerController(db, log)
	monitorController := controllers.NewMonitorController(db, log)
	
	// 注册路由
	registerRoutes(router, userController, certController, serverController, monitorController)
	
	// 创建HTTP服务器
	addr := fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	return &Server{
		router: router,
		server: server,
		logger: log,
		config: cfg,
	}
}

// 注册路由
func registerRoutes(router *gin.Engine, 
	userController *controllers.UserController,
	certController *controllers.CertificateController,
	serverController *controllers.ServerController,
	monitorController *controllers.MonitorController) {
	
	// API版本
	v1 := router.Group("/api/v1")
	
	// 公开路由
	public := v1.Group("/")
	{
		// 健康检查
		public.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
		
		// 用户认证
		public.POST("/auth/login", userController.Login)
		public.POST("/auth/register", userController.Register)
	}
	
	// 需要认证的路由
	authorized := v1.Group("/")
	authorized.Use(middleware.Auth())
	{
		// 用户相关
		authorized.GET("/users/me", userController.GetCurrentUser)
		authorized.PUT("/users/me", userController.UpdateCurrentUser)
		authorized.PUT("/users/me/password", userController.ChangePassword)
		
		// 证书相关
		authorized.GET("/certificates", certController.ListCertificates)
		authorized.POST("/certificates", certController.CreateCertificate)
		authorized.GET("/certificates/:id", certController.GetCertificate)
		authorized.PUT("/certificates/:id", certController.UpdateCertificate)
		authorized.DELETE("/certificates/:id", certController.DeleteCertificate)
		authorized.POST("/certificates/:id/verify", certController.VerifyDNS)
		authorized.POST("/certificates/:id/issue", certController.IssueCertificate)
		authorized.POST("/certificates/:id/renew", certController.RenewCertificate)
		authorized.GET("/certificates/:id/download", certController.DownloadCertificate)
		
		// 服务器相关
		authorized.GET("/servers", serverController.ListServers)
		authorized.POST("/servers", serverController.CreateServer)
		authorized.GET("/servers/:id", serverController.GetServer)
		authorized.PUT("/servers/:id", serverController.UpdateServer)
		authorized.DELETE("/servers/:id", serverController.DeleteServer)
		authorized.POST("/servers/:id/test", serverController.TestConnection)
		authorized.POST("/servers/:id/deploy", serverController.DeployCertificate)
		
		// 监控相关
		authorized.GET("/monitors", monitorController.ListMonitors)
		authorized.POST("/monitors", monitorController.CreateMonitor)
		authorized.GET("/monitors/:id", monitorController.GetMonitor)
		authorized.PUT("/monitors/:id", monitorController.UpdateMonitor)
		authorized.DELETE("/monitors/:id", monitorController.DeleteMonitor)
		authorized.POST("/monitors/:id/check", monitorController.CheckCertificate)
	}
	
	// 管理员路由
	admin := v1.Group("/admin")
	admin.Use(middleware.Auth(), middleware.AdminOnly())
	{
		// 用户管理
		admin.GET("/users", userController.ListUsers)
		admin.POST("/users", userController.CreateUser)
		admin.GET("/users/:id", userController.GetUser)
		admin.PUT("/users/:id", userController.UpdateUser)
		admin.DELETE("/users/:id", userController.DeleteUser)
		
		// 系统设置
		admin.GET("/settings", userController.GetSettings)
		admin.PUT("/settings", userController.UpdateSettings)
	}
}

// Start 启动HTTP服务器
func (s *Server) Start() error {
	return s.server.ListenAndServe()
}

// Shutdown 优雅关闭HTTP服务器
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}
