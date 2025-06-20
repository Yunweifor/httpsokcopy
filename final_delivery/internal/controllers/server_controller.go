package controllers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/httpsok/internal/database"
	"github.com/httpsok/internal/logger"
	"github.com/httpsok/internal/models"
)

// ServerController 服务器控制器
type ServerController struct {
	db     *database.Connection
	logger logger.Logger
}

// NewServerController 创建服务器控制器
func NewServerController(db *database.Connection, log logger.Logger) *ServerController {
	return &ServerController{
		db:     db,
		logger: log,
	}
}

// ListServers 获取服务器列表
func (c *ServerController) ListServers(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// 分页参数
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "10"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}
	offset := (page - 1) * pageSize

	// 搜索参数
	search := ctx.Query("search")
	searchCondition := ""
	searchParams := []interface{}{}
	if search != "" {
		searchCondition = "AND (name LIKE ? OR hostname LIKE ? OR ip_address LIKE ?)"
		searchParams = append(searchParams, "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// 查询服务器列表
	query := fmt.Sprintf(`
		SELECT id, name, hostname, ip_address, server_type, os_type, os_version, 
		       version, port, auth_type, username, status, auto_deploy, 
		       last_check_at, notes, created_at 
		FROM servers 
		WHERE user_id = ? %s
		ORDER BY id DESC LIMIT ? OFFSET ?
	`, searchCondition)

	params := append([]interface{}{userID}, searchParams...)
	params = append(params, pageSize, offset)

	rows, err := c.db.Query(query, params...)
	if err != nil {
		c.logger.Error("Failed to query servers", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		var server models.Server
		err := rows.Scan(
			&server.ID, &server.Name, &server.Hostname, &server.IPAddress, &server.ServerType,
			&server.OSType, &server.OSVersion, &server.Version, &server.Port, &server.AuthType,
			&server.Username, &server.Status, &server.AutoDeploy, &server.LastCheckAt,
			&server.Notes, &server.CreatedAt,
		)
		if err != nil {
			c.logger.Error("Failed to scan server row", err)
			continue
		}
		servers = append(servers, server)
	}

	// 获取总数
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM servers WHERE user_id = ? %s", searchCondition)
	var total int
	err = c.db.QueryRow(countQuery, append([]interface{}{userID}, searchParams...)...).Scan(&total)
	if err != nil {
		c.logger.Error("Failed to count servers", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"servers": servers,
		"pagination": gin.H{
			"page":      page,
			"page_size": pageSize,
			"total":     total,
		},
	})
}

// GetServer 获取服务器详情
func (c *ServerController) GetServer(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	serverID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	// 查询服务器
	var server models.Server
	query := `
		SELECT id, name, hostname, ip_address, server_type, os_type, os_version, 
		       version, port, auth_type, username, status, auto_deploy, 
		       last_check_at, notes, created_at 
		FROM servers 
		WHERE id = ? AND user_id = ?
	`
	err = c.db.QueryRow(query, serverID, userID).Scan(
		&server.ID, &server.Name, &server.Hostname, &server.IPAddress, &server.ServerType,
		&server.OSType, &server.OSVersion, &server.Version, &server.Port, &server.AuthType,
		&server.Username, &server.Status, &server.AutoDeploy, &server.LastCheckAt,
		&server.Notes, &server.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
			return
		}
		c.logger.Error("Failed to query server", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 查询部署的证书
	rows, err := c.db.Query(`
		SELECT d.id, d.certificate_id, d.cert_path, d.key_path, d.chain_path, 
		       d.config_path, d.auto_deploy, d.reload_service, d.status, 
		       d.last_deployed_at, c.domain_main, c.status as cert_status
		FROM deployments d
		JOIN certificates c ON d.certificate_id = c.id
		WHERE d.server_id = ?
	`, serverID)
	if err != nil {
		c.logger.Error("Failed to query deployments", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer rows.Close()

	var deployments []gin.H
	for rows.Next() {
		var deploy models.Deployment
		var certID uint64
		var domainMain, certStatus string
		err := rows.Scan(
			&deploy.ID, &certID, &deploy.CertPath, &deploy.KeyPath, &deploy.ChainPath,
			&deploy.ConfigPath, &deploy.AutoDeploy, &deploy.ReloadService, &deploy.Status,
			&deploy.LastDeployedAt, &domainMain, &certStatus,
		)
		if err != nil {
			c.logger.Error("Failed to scan deployment row", err)
			continue
		}
		deploy.ServerID = serverID
		deploy.CertificateID = certID
		deployments = append(deployments, gin.H{
			"deployment": deploy,
			"certificate": gin.H{
				"id":          certID,
				"domain_main": domainMain,
				"status":      certStatus,
			},
		})
	}

	ctx.JSON(http.StatusOK, gin.H{
		"server":      server,
		"deployments": deployments,
	})
}

// CreateServer 创建服务器
func (c *ServerController) CreateServer(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		Name        string `json:"name" binding:"required"`
		Hostname    string `json:"hostname" binding:"required"`
		IPAddress   string `json:"ip_address" binding:"required"`
		ServerType  string `json:"server_type" binding:"required"`
		OSType      string `json:"os_type" binding:"required"`
		OSVersion   string `json:"os_version"`
		Version     string `json:"version"`
		Port        int    `json:"port"`
		AuthType    string `json:"auth_type" binding:"required"`
		Username    string `json:"username" binding:"required"`
		Password    string `json:"password"`
		PrivateKey  string `json:"private_key"`
		AutoDeploy  bool   `json:"auto_deploy"`
		Notes       string `json:"notes"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 验证服务器类型
	if req.ServerType != "nginx" && req.ServerType != "apache" && req.ServerType != "other" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server type"})
		return
	}

	// 验证认证类型
	if req.AuthType != "password" && req.AuthType != "key" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid authentication type"})
		return
	}

	// 验证认证信息
	if req.AuthType == "password" && req.Password == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Password is required for password authentication"})
		return
	}
	if req.AuthType == "key" && req.PrivateKey == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Private key is required for key authentication"})
		return
	}

	// 设置默认端口
	if req.Port <= 0 {
		req.Port = 22
	}

	// 准备认证数据
	var authData sql.NullString
	if req.AuthType == "password" {
		authData = sql.NullString{String: req.Password, Valid: true}
	} else {
		authData = sql.NullString{String: req.PrivateKey, Valid: true}
	}

	// 准备可选字段
	var osVersion, version, notes sql.NullString
	if req.OSVersion != "" {
		osVersion = sql.NullString{String: req.OSVersion, Valid: true}
	}
	if req.Version != "" {
		version = sql.NullString{String: req.Version, Valid: true}
	}
	if req.Notes != "" {
		notes = sql.NullString{String: req.Notes, Valid: true}
	}

	// 插入服务器记录
	result, err := c.db.Exec(`
		INSERT INTO servers (
			name, hostname, ip_address, server_type, os_type, os_version, 
			version, port, auth_type, username, auth_data, status, 
			auto_deploy, notes, user_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		req.Name, req.Hostname, req.IPAddress, req.ServerType, req.OSType, osVersion,
		version, req.Port, req.AuthType, req.Username, authData, "pending",
		req.AutoDeploy, notes, userID,
	)
	if err != nil {
		c.logger.Error("Failed to insert server", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	serverID, err := result.LastInsertId()
	if err != nil {
		c.logger.Error("Failed to get last insert ID", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{
		"id":          serverID,
		"name":        req.Name,
		"hostname":    req.Hostname,
		"ip_address":  req.IPAddress,
		"server_type": req.ServerType,
		"os_type":     req.OSType,
		"os_version":  req.OSVersion,
		"version":     req.Version,
		"port":        req.Port,
		"auth_type":   req.AuthType,
		"username":    req.Username,
		"status":      "pending",
		"auto_deploy": req.AutoDeploy,
		"notes":       req.Notes,
	})
}

// UpdateServer 更新服务器
func (c *ServerController) UpdateServer(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	serverID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var req struct {
		Name        *string `json:"name"`
		Hostname    *string `json:"hostname"`
		IPAddress   *string `json:"ip_address"`
		ServerType  *string `json:"server_type"`
		OSType      *string `json:"os_type"`
		OSVersion   *string `json:"os_version"`
		Version     *string `json:"version"`
		Port        *int    `json:"port"`
		AuthType    *string `json:"auth_type"`
		Username    *string `json:"username"`
		Password    *string `json:"password"`
		PrivateKey  *string `json:"private_key"`
		AutoDeploy  *bool   `json:"auto_deploy"`
		Notes       *string `json:"notes"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 检查服务器是否存在
	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM servers WHERE id = ? AND user_id = ?", serverID, userID).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check server", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count == 0 {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// 验证服务器类型
	if req.ServerType != nil && *req.ServerType != "nginx" && *req.ServerType != "apache" && *req.ServerType != "other" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server type"})
		return
	}

	// 验证认证类型
	if req.AuthType != nil && *req.AuthType != "password" && *req.AuthType != "key" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid authentication type"})
		return
	}

	// 构建更新语句
	updates := []string{}
	args := []interface{}{}

	if req.Name != nil {
		updates = append(updates, "name = ?")
		args = append(args, *req.Name)
	}

	if req.Hostname != nil {
		updates = append(updates, "hostname = ?")
		args = append(args, *req.Hostname)
	}

	if req.IPAddress != nil {
		updates = append(updates, "ip_address = ?")
		args = append(args, *req.IPAddress)
	}

	if req.ServerType != nil {
		updates = append(updates, "server_type = ?")
		args = append(args, *req.ServerType)
	}

	if req.OSType != nil {
		updates = append(updates, "os_type = ?")
		args = append(args, *req.OSType)
	}

	if req.OSVersion != nil {
		updates = append(updates, "os_version = ?")
		args = append(args, sql.NullString{String: *req.OSVersion, Valid: *req.OSVersion != ""})
	}

	if req.Version != nil {
		updates = append(updates, "version = ?")
		args = append(args, sql.NullString{String: *req.Version, Valid: *req.Version != ""})
	}

	if req.Port != nil {
		if *req.Port <= 0 {
			*req.Port = 22
		}
		updates = append(updates, "port = ?")
		args = append(args, *req.Port)
	}

	if req.AuthType != nil {
		updates = append(updates, "auth_type = ?")
		args = append(args, *req.AuthType)
	}

	if req.Username != nil {
		updates = append(updates, "username = ?")
		args = append(args, *req.Username)
	}

	// 更新认证数据
	if req.Password != nil && (req.AuthType == nil || *req.AuthType == "password") {
		updates = append(updates, "auth_data = ?")
		args = append(args, sql.NullString{String: *req.Password, Valid: true})
	} else if req.PrivateKey != nil && (req.AuthType == nil || *req.AuthType == "key") {
		updates = append(updates, "auth_data = ?")
		args = append(args, sql.NullString{String: *req.PrivateKey, Valid: true})
	}

	if req.AutoDeploy != nil {
		updates = append(updates, "auto_deploy = ?")
		args = append(args, *req.AutoDeploy)
	}

	if req.Notes != nil {
		updates = append(updates, "notes = ?")
		args = append(args, sql.NullString{String: *req.Notes, Valid: *req.Notes != ""})
	}

	if len(updates) == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	// 执行更新
	query := fmt.Sprintf("UPDATE servers SET %s WHERE id = ? AND user_id = ?", strings.Join(updates, ", "))
	args = append(args, serverID, userID)

	_, err = c.db.Exec(query, args...)
	if err != nil {
		c.logger.Error("Failed to update server", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 获取更新后的服务器
	var server models.Server
	err = c.db.QueryRow(`
		SELECT id, name, hostname, ip_address, server_type, os_type, os_version, 
		       version, port, auth_type, username, status, auto_deploy, 
		       last_check_at, notes, created_at 
		FROM servers 
		WHERE id = ? AND user_id = ?
	`, serverID, userID).Scan(
		&server.ID, &server.Name, &server.Hostname, &server.IPAddress, &server.ServerType,
		&server.OSType, &server.OSVersion, &server.Version, &server.Port, &server.AuthType,
		&server.Username, &server.Status, &server.AutoDeploy, &server.LastCheckAt,
		&server.Notes, &server.CreatedAt,
	)
	if err != nil {
		c.logger.Error("Failed to query updated server", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, server)
}

// DeleteServer 删除服务器
func (c *ServerController) DeleteServer(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	serverID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	// 检查服务器是否存在
	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM servers WHERE id = ? AND user_id = ?", serverID, userID).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check server", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count == 0 {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// 开始事务
	tx, err := c.db.Begin()
	if err != nil {
		c.logger.Error("Failed to begin transaction", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// 删除部署记录
	_, err = tx.Exec("DELETE FROM deployments WHERE server_id = ?", serverID)
	if err != nil {
		c.logger.Error("Failed to delete deployments", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 删除服务器
	_, err = tx.Exec("DELETE FROM servers WHERE id = ? AND user_id = ?", serverID, userID)
	if err != nil {
		c.logger.Error("Failed to delete server", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 提交事务
	err = tx.Commit()
	if err != nil {
		c.logger.Error("Failed to commit transaction", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Server deleted successfully"})
}

// TestConnection 测试服务器连接
func (c *ServerController) TestConnection(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	serverID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	// 获取服务器信息
	var server models.Server
	err = c.db.QueryRow(`
		SELECT hostname, ip_address, port, auth_type, username, auth_data 
		FROM servers 
		WHERE id = ? AND user_id = ?
	`, serverID, userID).Scan(
		&server.Hostname, &server.IPAddress, &server.Port, &server.AuthType,
		&server.Username, &server.AuthData,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
			return
		}
		c.logger.Error("Failed to query server", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 模拟连接测试
	// 实际实现中应该尝试SSH连接
	c.logger.Infof("Testing connection to %s:%d with user %s", server.IPAddress, server.Port, server.Username)
	
	// 更新服务器状态和最后检查时间
	_, err = c.db.Exec("UPDATE servers SET status = ?, last_check_at = ? WHERE id = ?", "normal", time.Now(), serverID)
	if err != nil {
		c.logger.Error("Failed to update server status", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Connection test successful",
		"server_info": gin.H{
			"hostname":   server.Hostname,
			"ip_address": server.IPAddress,
			"port":       server.Port,
			"username":   server.Username,
			"status":     "normal",
		},
	})
}

// DeployCertificate 部署证书到服务器
func (c *ServerController) DeployCertificate(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	serverID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server ID"})
		return
	}

	var req struct {
		CertificateID uint64 `json:"certificate_id" binding:"required"`
		CertPath      string `json:"cert_path" binding:"required"`
		KeyPath       string `json:"key_path" binding:"required"`
		ChainPath     string `json:"chain_path"`
		ConfigPath    string `json:"config_path"`
		AutoDeploy    bool   `json:"auto_deploy"`
		ReloadService bool   `json:"reload_service"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 检查服务器是否存在
	var serverCount int
	err = c.db.QueryRow("SELECT COUNT(*) FROM servers WHERE id = ? AND user_id = ?", serverID, userID).Scan(&serverCount)
	if err != nil {
		c.logger.Error("Failed to check server", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if serverCount == 0 {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// 检查证书是否存在
	var certCount int
	err = c.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE id = ? AND user_id = ? AND status = 'issued'", req.CertificateID, userID).Scan(&certCount)
	if err != nil {
		c.logger.Error("Failed to check certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if certCount == 0 {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found or not issued"})
		return
	}

	// 检查是否已存在部署记录
	var deployCount int
	err = c.db.QueryRow("SELECT COUNT(*) FROM deployments WHERE server_id = ? AND certificate_id = ?", serverID, req.CertificateID).Scan(&deployCount)
	if err != nil {
		c.logger.Error("Failed to check deployment", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	var deployID int64
	if deployCount > 0 {
		// 更新现有部署记录
		_, err = c.db.Exec(`
			UPDATE deployments 
			SET cert_path = ?, key_path = ?, chain_path = ?, config_path = ?, 
			    auto_deploy = ?, reload_service = ?, status = ?, last_deployed_at = ? 
			WHERE server_id = ? AND certificate_id = ?
		`,
			req.CertPath, req.KeyPath,
			sql.NullString{String: req.ChainPath, Valid: req.ChainPath != ""},
			sql.NullString{String: req.ConfigPath, Valid: req.ConfigPath != ""},
			req.AutoDeploy, req.ReloadService, "pending", time.Now(),
			serverID, req.CertificateID,
		)
		if err != nil {
			c.logger.Error("Failed to update deployment", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		// 获取部署ID
		err = c.db.QueryRow("SELECT id FROM deployments WHERE server_id = ? AND certificate_id = ?", serverID, req.CertificateID).Scan(&deployID)
		if err != nil {
			c.logger.Error("Failed to get deployment ID", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
	} else {
		// 创建新的部署记录
		result, err := c.db.Exec(`
			INSERT INTO deployments (
				server_id, certificate_id, cert_path, key_path, chain_path, 
				config_path, auto_deploy, reload_service, status, last_deployed_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			serverID, req.CertificateID, req.CertPath, req.KeyPath,
			sql.NullString{String: req.ChainPath, Valid: req.ChainPath != ""},
			sql.NullString{String: req.ConfigPath, Valid: req.ConfigPath != ""},
			req.AutoDeploy, req.ReloadService, "pending", time.Now(),
		)
		if err != nil {
			c.logger.Error("Failed to insert deployment", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		deployID, err = result.LastInsertId()
		if err != nil {
			c.logger.Error("Failed to get last insert ID", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
	}

	// 模拟部署过程
	// 实际实现中应该通过SSH连接部署证书
	c.logger.Infof("Deploying certificate %d to server %d", req.CertificateID, serverID)
	
	// 更新部署状态
	_, err = c.db.Exec("UPDATE deployments SET status = ? WHERE id = ?", "deployed", deployID)
	if err != nil {
		c.logger.Error("Failed to update deployment status", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Certificate deployed successfully",
		"deployment": gin.H{
			"id":             deployID,
			"server_id":      serverID,
			"certificate_id": req.CertificateID,
			"cert_path":      req.CertPath,
			"key_path":       req.KeyPath,
			"chain_path":     req.ChainPath,
			"config_path":    req.ConfigPath,
			"auto_deploy":    req.AutoDeploy,
			"reload_service": req.ReloadService,
			"status":         "deployed",
			"deployed_at":    time.Now(),
		},
	})
}
