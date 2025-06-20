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
	"github.com/httpsok/internal/services"
)

// CertificateController 证书控制器
type CertificateController struct {
	db          *database.Connection
	logger      logger.Logger
	acmeService *services.ACMEService
}

// NewCertificateController 创建证书控制器
func NewCertificateController(db *database.Connection, log logger.Logger) *CertificateController {
	return &CertificateController{
		db:          db,
		logger:      log,
		acmeService: services.NewACMEService(log),
	}
}

// ListCertificates 获取证书列表
func (c *CertificateController) ListCertificates(ctx *gin.Context) {
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
		searchCondition = "AND (domain_main LIKE ? OR notes LIKE ?)"
		searchParams = append(searchParams, "%"+search+"%", "%"+search+"%")
	}

	// 查询证书列表
	query := fmt.Sprintf(`
		SELECT id, domain_main, domain_sans, ca_type, encryption_type, status, 
		       valid_from, valid_to, auto_renew, renew_before_days, notes, user_id, created_at 
		FROM certificates 
		WHERE user_id = ? %s
		ORDER BY id DESC LIMIT ? OFFSET ?
	`, searchCondition)

	params := append([]interface{}{userID}, searchParams...)
	params = append(params, pageSize, offset)

	rows, err := c.db.Query(query, params...)
	if err != nil {
		c.logger.Error("Failed to query certificates", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer rows.Close()

	var certificates []models.Certificate
	for rows.Next() {
		var cert models.Certificate
		err := rows.Scan(
			&cert.ID, &cert.DomainMain, &cert.DomainSANs, &cert.CAType, &cert.EncryptionType,
			&cert.Status, &cert.ValidFrom, &cert.ValidTo, &cert.AutoRenew, &cert.RenewBeforeDays,
			&cert.Notes, &cert.UserID, &cert.CreatedAt,
		)
		if err != nil {
			c.logger.Error("Failed to scan certificate row", err)
			continue
		}
		certificates = append(certificates, cert)
	}

	// 获取总数
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM certificates WHERE user_id = ? %s", searchCondition)
	var total int
	err = c.db.QueryRow(countQuery, append([]interface{}{userID}, searchParams...)...).Scan(&total)
	if err != nil {
		c.logger.Error("Failed to count certificates", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"certificates": certificates,
		"pagination": gin.H{
			"page":      page,
			"page_size": pageSize,
			"total":     total,
		},
	})
}

// GetCertificate 获取证书详情
func (c *CertificateController) GetCertificate(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	certID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	// 查询证书
	var cert models.Certificate
	query := `
		SELECT id, domain_main, domain_sans, ca_type, encryption_type, status, 
		       valid_from, valid_to, auto_renew, renew_before_days, notes, user_id, created_at 
		FROM certificates 
		WHERE id = ? AND user_id = ?
	`
	err = c.db.QueryRow(query, certID, userID).Scan(
		&cert.ID, &cert.DomainMain, &cert.DomainSANs, &cert.CAType, &cert.EncryptionType,
		&cert.Status, &cert.ValidFrom, &cert.ValidTo, &cert.AutoRenew, &cert.RenewBeforeDays,
		&cert.Notes, &cert.UserID, &cert.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}
		c.logger.Error("Failed to query certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 查询DNS验证记录
	rows, err := c.db.Query(`
		SELECT id, host_record, record_type, record_value, status, verified_at, created_at 
		FROM dns_validations 
		WHERE certificate_id = ?
	`, certID)
	if err != nil {
		c.logger.Error("Failed to query DNS validations", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer rows.Close()

	var dnsValidations []models.DNSValidation
	for rows.Next() {
		var dns models.DNSValidation
		err := rows.Scan(
			&dns.ID, &dns.HostRecord, &dns.RecordType, &dns.RecordValue,
			&dns.Status, &dns.VerifiedAt, &dns.CreatedAt,
		)
		if err != nil {
			c.logger.Error("Failed to scan DNS validation row", err)
			continue
		}
		dns.CertificateID = certID
		dnsValidations = append(dnsValidations, dns)
	}

	// 查询部署记录
	rows, err = c.db.Query(`
		SELECT d.id, d.server_id, d.cert_path, d.key_path, d.chain_path, d.config_path, 
		       d.auto_deploy, d.reload_service, d.status, d.last_deployed_at, d.created_at,
		       s.name, s.hostname, s.ip_address, s.server_type, s.status as server_status
		FROM deployments d
		JOIN servers s ON d.server_id = s.id
		WHERE d.certificate_id = ?
	`, certID)
	if err != nil {
		c.logger.Error("Failed to query deployments", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer rows.Close()

	var deployments []gin.H
	for rows.Next() {
		var deploy models.Deployment
		var serverName, hostname, ipAddress, serverType, serverStatus string
		err := rows.Scan(
			&deploy.ID, &deploy.ServerID, &deploy.CertPath, &deploy.KeyPath, &deploy.ChainPath, &deploy.ConfigPath,
			&deploy.AutoDeploy, &deploy.ReloadService, &deploy.Status, &deploy.LastDeployedAt, &deploy.CreatedAt,
			&serverName, &hostname, &ipAddress, &serverType, &serverStatus,
		)
		if err != nil {
			c.logger.Error("Failed to scan deployment row", err)
			continue
		}
		deploy.CertificateID = certID
		deployments = append(deployments, gin.H{
			"deployment": deploy,
			"server": gin.H{
				"id":         deploy.ServerID,
				"name":       serverName,
				"hostname":   hostname,
				"ip_address": ipAddress,
				"type":       serverType,
				"status":     serverStatus,
			},
		})
	}

	ctx.JSON(http.StatusOK, gin.H{
		"certificate":     cert,
		"dns_validations": dnsValidations,
		"deployments":     deployments,
	})
}

// CreateCertificate 创建证书
func (c *CertificateController) CreateCertificate(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		DomainMain     string   `json:"domain_main" binding:"required"`
		DomainSANs     []string `json:"domain_sans"`
		CAType         string   `json:"ca_type" binding:"required"`
		EncryptionType string   `json:"encryption_type" binding:"required"`
		AutoRenew      bool     `json:"auto_renew"`
		RenewBeforeDays int      `json:"renew_before_days"`
		Notes          string   `json:"notes"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 验证CA类型和加密类型
	if req.CAType != "letsencrypt" && req.CAType != "zerossl" && req.CAType != "google" && req.CAType != "other" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CA type"})
		return
	}
	if req.EncryptionType != "ECC" && req.EncryptionType != "RSA" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid encryption type"})
		return
	}

	// 验证域名格式
	if !isValidDomain(req.DomainMain) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid main domain format"})
		return
	}
	for _, san := range req.DomainSANs {
		if !isValidDomain(san) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SAN domain format: " + san})
			return
		}
	}

	// 设置默认值
	if req.RenewBeforeDays <= 0 {
		req.RenewBeforeDays = 30
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

	// 插入证书记录
	var domainSANs sql.NullString
	if len(req.DomainSANs) > 0 {
		domainSANs = sql.NullString{String: strings.Join(req.DomainSANs, ","), Valid: true}
	}

	var notes sql.NullString
	if req.Notes != "" {
		notes = sql.NullString{String: req.Notes, Valid: true}
	}

	result, err := tx.Exec(`
		INSERT INTO certificates (
			domain_main, domain_sans, ca_type, encryption_type, status, 
			auto_renew, renew_before_days, notes, user_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		req.DomainMain, domainSANs, req.CAType, req.EncryptionType, "pending",
		req.AutoRenew, req.RenewBeforeDays, notes, userID,
	)
	if err != nil {
		c.logger.Error("Failed to insert certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	certID, err := result.LastInsertId()
	if err != nil {
		c.logger.Error("Failed to get last insert ID", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 生成DNS验证记录
	dnsChallenge, err := c.acmeService.GenerateDNSChallenge(req.DomainMain)
	if err != nil {
		c.logger.Error("Failed to generate DNS challenge", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate DNS challenge"})
		return
	}

	_, err = tx.Exec(`
		INSERT INTO dns_validations (
			certificate_id, host_record, record_type, record_value, status
		) VALUES (?, ?, ?, ?, ?)
	`,
		certID, dnsChallenge.HostRecord, dnsChallenge.RecordType, dnsChallenge.RecordValue, "pending",
	)
	if err != nil {
		c.logger.Error("Failed to insert DNS validation", err)
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

	ctx.JSON(http.StatusCreated, gin.H{
		"id":           certID,
		"domain_main":  req.DomainMain,
		"domain_sans":  req.DomainSANs,
		"ca_type":      req.CAType,
		"encryption_type": req.EncryptionType,
		"status":       "pending",
		"auto_renew":   req.AutoRenew,
		"dns_challenge": gin.H{
			"host_record": dnsChallenge.HostRecord,
			"record_type": dnsChallenge.RecordType,
			"record_value": dnsChallenge.RecordValue,
		},
	})
}

// UpdateCertificate 更新证书
func (c *CertificateController) UpdateCertificate(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	certID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	var req struct {
		AutoRenew      *bool   `json:"auto_renew"`
		RenewBeforeDays *int    `json:"renew_before_days"`
		Notes          *string `json:"notes"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 检查证书是否存在
	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE id = ? AND user_id = ?", certID, userID).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count == 0 {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	// 构建更新语句
	updates := []string{}
	args := []interface{}{}

	if req.AutoRenew != nil {
		updates = append(updates, "auto_renew = ?")
		args = append(args, *req.AutoRenew)
	}

	if req.RenewBeforeDays != nil {
		if *req.RenewBeforeDays <= 0 {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Renew before days must be positive"})
			return
		}
		updates = append(updates, "renew_before_days = ?")
		args = append(args, *req.RenewBeforeDays)
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
	query := fmt.Sprintf("UPDATE certificates SET %s WHERE id = ? AND user_id = ?", strings.Join(updates, ", "))
	args = append(args, certID, userID)

	_, err = c.db.Exec(query, args...)
	if err != nil {
		c.logger.Error("Failed to update certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 获取更新后的证书
	var cert models.Certificate
	err = c.db.QueryRow(`
		SELECT id, domain_main, domain_sans, ca_type, encryption_type, status, 
		       valid_from, valid_to, auto_renew, renew_before_days, notes, user_id, created_at 
		FROM certificates 
		WHERE id = ? AND user_id = ?
	`, certID, userID).Scan(
		&cert.ID, &cert.DomainMain, &cert.DomainSANs, &cert.CAType, &cert.EncryptionType,
		&cert.Status, &cert.ValidFrom, &cert.ValidTo, &cert.AutoRenew, &cert.RenewBeforeDays,
		&cert.Notes, &cert.UserID, &cert.CreatedAt,
	)
	if err != nil {
		c.logger.Error("Failed to query updated certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, cert)
}

// DeleteCertificate 删除证书
func (c *CertificateController) DeleteCertificate(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	certID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	// 检查证书是否存在
	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE id = ? AND user_id = ?", certID, userID).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count == 0 {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
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

	// 删除DNS验证记录
	_, err = tx.Exec("DELETE FROM dns_validations WHERE certificate_id = ?", certID)
	if err != nil {
		c.logger.Error("Failed to delete DNS validations", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 删除部署记录
	_, err = tx.Exec("DELETE FROM deployments WHERE certificate_id = ?", certID)
	if err != nil {
		c.logger.Error("Failed to delete deployments", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 删除证书
	_, err = tx.Exec("DELETE FROM certificates WHERE id = ? AND user_id = ?", certID, userID)
	if err != nil {
		c.logger.Error("Failed to delete certificate", err)
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

	ctx.JSON(http.StatusOK, gin.H{"message": "Certificate deleted successfully"})
}

// VerifyDNS 验证DNS记录
func (c *CertificateController) VerifyDNS(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	certID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	// 检查证书是否存在
	var domainMain string
	err = c.db.QueryRow("SELECT domain_main FROM certificates WHERE id = ? AND user_id = ?", certID, userID).Scan(&domainMain)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}
		c.logger.Error("Failed to query certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 获取DNS验证记录
	var dnsValidation models.DNSValidation
	err = c.db.QueryRow(`
		SELECT id, host_record, record_type, record_value, status 
		FROM dns_validations 
		WHERE certificate_id = ? 
		ORDER BY id DESC LIMIT 1
	`, certID).Scan(
		&dnsValidation.ID, &dnsValidation.HostRecord, &dnsValidation.RecordType,
		&dnsValidation.RecordValue, &dnsValidation.Status,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "DNS validation record not found"})
			return
		}
		c.logger.Error("Failed to query DNS validation", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 验证DNS记录
	verified, err := c.acmeService.VerifyDNSChallenge(domainMain, dnsValidation.HostRecord, dnsValidation.RecordType, dnsValidation.RecordValue)
	if err != nil {
		c.logger.Error("Failed to verify DNS challenge", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify DNS challenge"})
		return
	}

	if !verified {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "DNS verification failed", "verified": false})
		return
	}

	// 更新DNS验证记录状态
	_, err = c.db.Exec(`
		UPDATE dns_validations 
		SET status = ?, verified_at = ? 
		WHERE id = ?
	`, "verified", time.Now(), dnsValidation.ID)
	if err != nil {
		c.logger.Error("Failed to update DNS validation status", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "DNS verification successful", "verified": true})
}

// IssueCertificate 签发证书
func (c *CertificateController) IssueCertificate(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	certID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	// 获取证书信息
	var cert models.Certificate
	err = c.db.QueryRow(`
		SELECT id, domain_main, domain_sans, ca_type, encryption_type, status 
		FROM certificates 
		WHERE id = ? AND user_id = ?
	`, certID, userID).Scan(
		&cert.ID, &cert.DomainMain, &cert.DomainSANs, &cert.CAType, &cert.EncryptionType, &cert.Status,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}
		c.logger.Error("Failed to query certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 检查DNS验证状态
	var dnsStatus string
	err = c.db.QueryRow(`
		SELECT status 
		FROM dns_validations 
		WHERE certificate_id = ? 
		ORDER BY id DESC LIMIT 1
	`, certID).Scan(&dnsStatus)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "DNS validation record not found"})
			return
		}
		c.logger.Error("Failed to query DNS validation status", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if dnsStatus != "verified" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "DNS validation not completed"})
		return
	}

	// 解析域名列表
	domains := []string{cert.DomainMain}
	if cert.DomainSANs.Valid && cert.DomainSANs.String != "" {
		domains = append(domains, strings.Split(cert.DomainSANs.String, ",")...)
	}

	// 签发证书
	certData, err := c.acmeService.IssueCertificate(domains, cert.CAType, cert.EncryptionType)
	if err != nil {
		c.logger.Error("Failed to issue certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue certificate: " + err.Error()})
		return
	}

	// 更新证书数据
	now := time.Now()
	validTo := now.AddDate(0, 3, 0) // 假设证书有效期为3个月
	_, err = c.db.Exec(`
		UPDATE certificates 
		SET status = ?, valid_from = ?, valid_to = ?, cert_data = ?, key_data = ?, chain_data = ? 
		WHERE id = ?
	`,
		"issued", now, validTo, certData.Certificate, certData.PrivateKey, certData.Chain, certID,
	)
	if err != nil {
		c.logger.Error("Failed to update certificate data", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Certificate issued successfully",
		"certificate": gin.H{
			"id":          certID,
			"domain_main": cert.DomainMain,
			"status":      "issued",
			"valid_from":  now,
			"valid_to":    validTo,
		},
	})
}

// RenewCertificate 续期证书
func (c *CertificateController) RenewCertificate(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	certID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	// 获取证书信息
	var cert models.Certificate
	err = c.db.QueryRow(`
		SELECT id, domain_main, domain_sans, ca_type, encryption_type, status 
		FROM certificates 
		WHERE id = ? AND user_id = ?
	`, certID, userID).Scan(
		&cert.ID, &cert.DomainMain, &cert.DomainSANs, &cert.CAType, &cert.EncryptionType, &cert.Status,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}
		c.logger.Error("Failed to query certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if cert.Status != "issued" && cert.Status != "expired" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Certificate is not in a renewable state"})
		return
	}

	// 解析域名列表
	domains := []string{cert.DomainMain}
	if cert.DomainSANs.Valid && cert.DomainSANs.String != "" {
		domains = append(domains, strings.Split(cert.DomainSANs.String, ",")...)
	}

	// 续期证书
	certData, err := c.acmeService.RenewCertificate(domains, cert.CAType, cert.EncryptionType)
	if err != nil {
		c.logger.Error("Failed to renew certificate", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to renew certificate: " + err.Error()})
		return
	}

	// 更新证书数据
	now := time.Now()
	validTo := now.AddDate(0, 3, 0) // 假设证书有效期为3个月
	_, err = c.db.Exec(`
		UPDATE certificates 
		SET status = ?, valid_from = ?, valid_to = ?, cert_data = ?, key_data = ?, chain_data = ? 
		WHERE id = ?
	`,
		"issued", now, validTo, certData.Certificate, certData.PrivateKey, certData.Chain, certID,
	)
	if err != nil {
		c.logger.Error("Failed to update certificate data", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Certificate renewed successfully",
		"certificate": gin.H{
			"id":          certID,
			"domain_main": cert.DomainMain,
			"status":      "issued",
			"valid_from":  now,
			"valid_to":    validTo,
		},
	})
}

// DownloadCertificate 下载证书
func (c *CertificateController) DownloadCertificate(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	certID, err := strconv.ParseUint(ctx.Param("id"), 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	// 获取证书数据
	var cert models.Certificate
	err = c.db.QueryRow(`
		SELECT domain_main, cert_data, key_data, chain_data, status 
		FROM certificates 
		WHERE id = ? AND user_id = ?
	`, certID, userID).Scan(
		&cert.DomainMain, &cert.CertData, &cert.KeyData, &cert.ChainData, &cert.Status,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}
		c.logger.Error("Failed to query certificate data", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if cert.Status != "issued" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Certificate is not issued"})
		return
	}

	if !cert.CertData.Valid || !cert.KeyData.Valid {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Certificate data is not available"})
		return
	}

	// 获取下载格式
	format := ctx.DefaultQuery("format", "nginx")

	var response gin.H
	switch format {
	case "nginx":
		response = gin.H{
			"cert": cert.CertData.String,
			"key":  cert.KeyData.String,
			"chain": func() string {
				if cert.ChainData.Valid {
					return cert.ChainData.String
				}
				return ""
			}(),
		}
	case "apache":
		response = gin.H{
			"cert": cert.CertData.String,
			"key":  cert.KeyData.String,
			"chain": func() string {
				if cert.ChainData.Valid {
					return cert.ChainData.String
				}
				return ""
			}(),
		}
	case "pem":
		// 合并证书和链
		fullChain := cert.CertData.String
		if cert.ChainData.Valid {
			fullChain += "\n" + cert.ChainData.String
		}
		response = gin.H{
			"cert": cert.CertData.String,
			"key":  cert.KeyData.String,
			"fullchain": fullChain,
		}
	case "pfx":
		// 这里应该实现PFX格式转换，但为简化示例，仅返回错误
		ctx.JSON(http.StatusNotImplemented, gin.H{"error": "PFX format conversion not implemented"})
		return
	default:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid format"})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// 辅助函数：验证域名格式
func isValidDomain(domain string) bool {
	// 简单的域名验证，实际应用中应使用更复杂的验证
	return len(domain) > 0 && !strings.Contains(domain, " ") && strings.Contains(domain, ".")
}
