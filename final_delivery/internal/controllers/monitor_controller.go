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

// MonitorController 监控控制器
type MonitorController struct {
	db     *database.Connection
	logger logger.Logger
}

// NewMonitorController 创建监控控制器
func NewMonitorController(db *database.Connection, log logger.Logger) *MonitorController {
	return &MonitorController{
		db:     db,
		logger: log,
	}
}

// ListMonitors 获取监控列表
func (c *MonitorController) ListMonitors(ctx *gin.Context) {
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
		searchCondition = "AND (host LIKE ? OR ip_address LIKE ? OR notes LIKE ?)"
		searchParams = append(searchParams, "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// 排序参数
	sortBy := ctx.DefaultQuery("sort_by", "id")
	sortOrder := ctx.DefaultQuery("sort_order", "desc")
	
	// 验证排序字段
	validSortFields := map[string]bool{
		"id": true, "host": true, "valid_days": true, "last_check_at": true, "created_at": true,
	}
	if !validSortFields[sortBy] {
		sortBy = "id"
	}
	
	// 验证排序顺序
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	// 查询监控列表
	query := fmt.Sprintf(`
		SELECT id, host, port, ip_type, ip_address, certificate_id, 
		       check_interval, enabled, last_status, valid_days, 
		       cert_grade, encryption_type, notes, last_check_at, created_at 
		FROM monitors 
		WHERE user_id = ? %s
		ORDER BY %s %s LIMIT ? OFFSET ?
	`, searchCondition, sortBy, sortOrder)

	params := append([]interface{}{userID}, searchParams...)
	params = append(params, pageSize, offset)

	rows, err := c.db.Query(query, params...)
	if err != nil {
		c.logger.Error("Failed to query monitors", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer rows.Close()

	var monitors []models.Monitor
	for rows.Next() {
		var monitor models.Monitor
		err := rows.Scan(
			&monitor.ID, &monitor.Host, &monitor.Port, &monitor.IPType, &monitor.IPAddress,
			&monitor.CertificateID, &monitor.CheckInterval, &monitor.Enabled, &monitor.LastStatus,
			&monitor.ValidDays, &monitor.CertGrade, &monitor.EncryptionType, &monitor.Notes,
			&monitor.LastCheckAt, &monitor.CreatedAt,
		)
		if err != nil {
			c.logger.Error("Failed to scan monitor row", err)
			continue
		}
		monitors = append(monitors, monitor)
	}

	// 获取总数
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM monitors WHERE user_id = ? %s", searchCondition)
	var total int
	err = c.db.QueryRow(countQuery, append([]interface{}{userID}, searchParams...)...).Scan(&total)
	if err != nil {
		c.logger.Error("Failed to count monitors", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"monitors": monitors,
		"pagination": gin.H{
			"page":      page,
			"page_size": pageSize,
			"total":     total,
		},
	})
}

// GetMonitor 获取监控详情
func (c *MonitorController) GetMonitor(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	monitorID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid monitor ID"})
		return
	}

	// 查询监控
	var monitor models.Monitor
	query := `
		SELECT id, host, port, ip_type, ip_address, certificate_id, 
		       check_interval, enabled, last_status, valid_days, 
		       cert_grade, encryption_type, notes, last_check_at, created_at 
		FROM monitors 
		WHERE id = ? AND user_id = ?
	`
	err = c.db.QueryRow(query, monitorID, userID).Scan(
		&monitor.ID, &monitor.Host, &monitor.Port, &monitor.IPType, &monitor.IPAddress,
		&monitor.CertificateID, &monitor.CheckInterval, &monitor.Enabled, &monitor.LastStatus,
		&monitor.ValidDays, &monitor.CertGrade, &monitor.EncryptionType, &monitor.Notes,
		&monitor.LastCheckAt, &monitor.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Monitor not found"})
			return
		}
		c.logger.Error("Failed to query monitor", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 如果关联了证书，获取证书信息
	var certificate *models.Certificate
	if monitor.CertificateID.Valid {
		cert := models.Certificate{}
		err = c.db.QueryRow(`
			SELECT id, domain_main, domain_sans, ca_type, encryption_type, status, 
			       valid_from, valid_to 
			FROM certificates 
			WHERE id = ?
		`, monitor.CertificateID.Int64).Scan(
			&cert.ID, &cert.DomainMain, &cert.DomainSANs, &cert.CAType, &cert.EncryptionType,
			&cert.Status, &cert.ValidFrom, &cert.ValidTo,
		)
		if err != nil && err != sql.ErrNoRows {
			c.logger.Error("Failed to query certificate", err)
		} else if err == nil {
			certificate = &cert
		}
	}

	// 获取监控历史记录
	rows, err := c.db.Query(`
		SELECT check_time, status, valid_days, cert_grade, encryption_type, error_message 
		FROM monitor_history 
		WHERE monitor_id = ? 
		ORDER BY check_time DESC LIMIT 10
	`, monitorID)
	if err != nil {
		c.logger.Error("Failed to query monitor history", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer rows.Close()

	var history []gin.H
	for rows.Next() {
		var checkTime time.Time
		var status string
		var validDays sql.NullInt32
		var certGrade, encryptionType, errorMessage sql.NullString
		err := rows.Scan(&checkTime, &status, &validDays, &certGrade, &encryptionType, &errorMessage)
		if err != nil {
			c.logger.Error("Failed to scan monitor history row", err)
			continue
		}
		history = append(history, gin.H{
			"check_time":     checkTime,
			"status":         status,
			"valid_days":     validDays.Int32,
			"cert_grade":     certGrade.String,
			"encryption_type": encryptionType.String,
			"error_message":  errorMessage.String,
		})
	}

	response := gin.H{"monitor": monitor, "history": history}
	if certificate != nil {
		response["certificate"] = certificate
	}

	ctx.JSON(http.StatusOK, response)
}

// CreateMonitor 创建监控
func (c *MonitorController) CreateMonitor(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		Host          string  `json:"host" binding:"required"`
		Port          int     `json:"port" binding:"required"`
		IPType        string  `json:"ip_type" binding:"required"`
		IPAddress     string  `json:"ip_address"`
		CertificateID *uint64 `json:"certificate_id"`
		CheckInterval int     `json:"check_interval"`
		Enabled       bool    `json:"enabled"`
		Notes         string  `json:"notes"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 验证IP类型
	if req.IPType != "ipv4" && req.IPType != "ipv6" && req.IPType != "domain" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP type"})
		return
	}

	// 验证端口
	if req.Port <= 0 || req.Port > 65535 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid port number"})
		return
	}

	// 设置默认值
	if req.CheckInterval <= 0 {
		req.CheckInterval = 24 * 60 // 默认24小时
	}

	// 准备可选字段
	var ipAddress, notes sql.NullString
	if req.IPAddress != "" {
		ipAddress = sql.NullString{String: req.IPAddress, Valid: true}
	}
	if req.Notes != "" {
		notes = sql.NullString{String: req.Notes, Valid: true}
	}

	var certificateID sql.NullInt64
	if req.CertificateID != nil {
		// 检查证书是否存在
		var certCount int
		err := c.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE id = ? AND user_id = ?", *req.CertificateID, userID).Scan(&certCount)
		if err != nil {
			c.logger.Error("Failed to check certificate", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		if certCount == 0 {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Certificate not found"})
			return
		}
		certificateID = sql.NullInt64{Int64: int64(*req.CertificateID), Valid: true}
	}

	// 插入监控记录
	result, err := c.db.Exec(`
		INSERT INTO monitors (
			host, port, ip_type, ip_address, certificate_id, 
			check_interval, enabled, last_status, notes, user_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		req.Host, req.Port, req.IPType, ipAddress, certificateID,
		req.CheckInterval, req.Enabled, "pending", notes, userID,
	)
	if err != nil {
		c.logger.Error("Failed to insert monitor", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	monitorID, err := result.LastInsertId()
	if err != nil {
		c.logger.Error("Failed to get last insert ID", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{
		"id":            monitorID,
		"host":          req.Host,
		"port":          req.Port,
		"ip_type":       req.IPType,
		"ip_address":    req.IPAddress,
		"certificate_id": req.CertificateID,
		"check_interval": req.CheckInterval,
		"enabled":       req.Enabled,
		"last_status":   "pending",
		"notes":         req.Notes,
	})
}

// UpdateMonitor 更新监控
func (c *MonitorController) UpdateMonitor(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	monitorID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid monitor ID"})
		return
	}

	var req struct {
		Host          *string `json:"host"`
		Port          *int    `json:"port"`
		IPType        *string `json:"ip_type"`
		IPAddress     *string `json:"ip_address"`
		CertificateID *uint64 `json:"certificate_id"`
		CheckInterval *int    `json:"check_interval"`
		Enabled       *bool   `json:"enabled"`
		Notes         *string `json:"notes"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 检查监控是否存在
	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM monitors WHERE id = ? AND user_id = ?", monitorID, userID).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check monitor", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count == 0 {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Monitor not found"})
		return
	}

	// 验证IP类型
	if req.IPType != nil && *req.IPType != "ipv4" && *req.IPType != "ipv6" && *req.IPType != "domain" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP type"})
		return
	}

	// 验证端口
	if req.Port != nil && (*req.Port <= 0 || *req.Port > 65535) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid port number"})
		return
	}

	// 验证检查间隔
	if req.CheckInterval != nil && *req.CheckInterval <= 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid check interval"})
		return
	}

	// 构建更新语句
	updates := []string{}
	args := []interface{}{}

	if req.Host != nil {
		updates = append(updates, "host = ?")
		args = append(args, *req.Host)
	}

	if req.Port != nil {
		updates = append(updates, "port = ?")
		args = append(args, *req.Port)
	}

	if req.IPType != nil {
		updates = append(updates, "ip_type = ?")
		args = append(args, *req.IPType)
	}

	if req.IPAddress != nil {
		updates = append(updates, "ip_address = ?")
		args = append(args, sql.NullString{String: *req.IPAddress, Valid: *req.IPAddress != ""})
	}

	if req.CertificateID != nil {
		// 检查证书是否存在
		var certCount int
		err := c.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE id = ? AND user_id = ?", *req.CertificateID, userID).Scan(&certCount)
		if err != nil {
			c.logger.Error("Failed to check certificate", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		if certCount == 0 {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Certificate not found"})
			return
		}
		updates = append(updates, "certificate_id = ?")
		args = append(args, sql.NullInt64{Int64: int64(*req.CertificateID), Valid: true})
	}

	if req.CheckInterval != nil {
		updates = append(updates, "check_interval = ?")
		args = append(args, *req.CheckInterval)
	}

	if req.Enabled != nil {
		updates = append(updates, "enabled = ?")
		args = append(args, *req.Enabled)
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
	query := fmt.Sprintf("UPDATE monitors SET %s WHERE id = ? AND user_id = ?", strings.Join(updates, ", "))
	args = append(args, monitorID, userID)

	_, err = c.db.Exec(query, args...)
	if err != nil {
		c.logger.Error("Failed to update monitor", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 获取更新后的监控
	var monitor models.Monitor
	err = c.db.QueryRow(`
		SELECT id, host, port, ip_type, ip_address, certificate_id, 
		       check_interval, enabled, last_status, valid_days, 
		       cert_grade, encryption_type, notes, last_check_at, created_at 
		FROM monitors 
		WHERE id = ? AND user_id = ?
	`, monitorID, userID).Scan(
		&monitor.ID, &monitor.Host, &monitor.Port, &monitor.IPType, &monitor.IPAddress,
		&monitor.CertificateID, &monitor.CheckInterval, &monitor.Enabled, &monitor.LastStatus,
		&monitor.ValidDays, &monitor.CertGrade, &monitor.EncryptionType, &monitor.Notes,
		&monitor.LastCheckAt, &monitor.CreatedAt,
	)
	if err != nil {
		c.logger.Error("Failed to query updated monitor", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, monitor)
}

// DeleteMonitor 删除监控
func (c *MonitorController) DeleteMonitor(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	monitorID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid monitor ID"})
		return
	}

	// 检查监控是否存在
	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM monitors WHERE id = ? AND user_id = ?", monitorID, userID).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check monitor", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count == 0 {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Monitor not found"})
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

	// 删除监控历史记录
	_, err = tx.Exec("DELETE FROM monitor_history WHERE monitor_id = ?", monitorID)
	if err != nil {
		c.logger.Error("Failed to delete monitor history", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 删除监控
	_, err = tx.Exec("DELETE FROM monitors WHERE id = ? AND user_id = ?", monitorID, userID)
	if err != nil {
		c.logger.Error("Failed to delete monitor", err)
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

	ctx.JSON(http.StatusOK, gin.H{"message": "Monitor deleted successfully"})
}

// CheckCertificate 检查证书状态
func (c *MonitorController) CheckCertificate(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	monitorID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid monitor ID"})
		return
	}

	// 获取监控信息
	var monitor models.Monitor
	err = c.db.QueryRow(`
		SELECT host, port, ip_type, ip_address 
		FROM monitors 
		WHERE id = ? AND user_id = ?
	`, monitorID, userID).Scan(
		&monitor.Host, &monitor.Port, &monitor.IPType, &monitor.IPAddress,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Monitor not found"})
			return
		}
		c.logger.Error("Failed to query monitor", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 模拟证书检查
	// 实际实现中应该连接服务器并获取证书信息
	c.logger.Infof("Checking certificate for %s:%d", monitor.Host, monitor.Port)
	
	// 生成模拟检查结果
	now := time.Now()
	validDays := 90
	certGrade := "A+"
	encryptionType := "ECC"
	status := "normal"

	// 更新监控状态
	_, err = c.db.Exec(`
		UPDATE monitors 
		SET last_status = ?, valid_days = ?, cert_grade = ?, 
		    encryption_type = ?, last_check_at = ? 
		WHERE id = ?
	`,
		status, validDays, certGrade, encryptionType, now, monitorID,
	)
	if err != nil {
		c.logger.Error("Failed to update monitor status", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 记录检查历史
	_, err = c.db.Exec(`
		INSERT INTO monitor_history (
			monitor_id, check_time, status, valid_days, 
			cert_grade, encryption_type
		) VALUES (?, ?, ?, ?, ?, ?)
	`,
		monitorID, now, status, validDays, certGrade, encryptionType,
	)
	if err != nil {
		c.logger.Error("Failed to insert monitor history", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Certificate check completed",
		"result": gin.H{
			"status":         status,
			"valid_days":     validDays,
			"cert_grade":     certGrade,
			"encryption_type": encryptionType,
			"check_time":     now,
		},
	})
}
