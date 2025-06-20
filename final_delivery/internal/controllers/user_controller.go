package controllers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/httpsok/internal/database"
	"github.com/httpsok/internal/logger"
	"github.com/httpsok/internal/models"
)

// UserController 用户控制器
type UserController struct {
	db     *database.Connection
	logger logger.Logger
}

// NewUserController 创建用户控制器
func NewUserController(db *database.Connection, log logger.Logger) *UserController {
	return &UserController{
		db:     db,
		logger: log,
	}
}

// Login 用户登录
func (c *UserController) Login(ctx *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 查询用户
	var user models.User
	query := "SELECT id, username, password_hash, role, status FROM users WHERE username = ? LIMIT 1"
	err := c.db.QueryRow(query, req.Username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.Status)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}
		c.logger.Error("Failed to query user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 检查用户状态
	if user.Status != "active" {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "Account is not active"})
		return
	}

	// 验证密码
	// TODO: 实现密码验证
	// if !utils.VerifyPassword(user.PasswordHash, req.Password) {
	//     ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
	//     return
	// }

	// 生成JWT令牌
	// TODO: 实现JWT令牌生成
	token := "sample_token_" + strconv.Itoa(int(user.ID))

	// 更新最后登录时间
	_, err = c.db.Exec("UPDATE users SET last_login_at = ? WHERE id = ?", time.Now(), user.ID)
	if err != nil {
		c.logger.Error("Failed to update last login time", err)
	}

	ctx.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

// Register 用户注册
func (c *UserController) Register(ctx *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
		FullName string `json:"full_name"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 检查用户名是否已存在
	var count int
	err := c.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", req.Username).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check username", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count > 0 {
		ctx.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	// 检查邮箱是否已存在
	err = c.db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", req.Email).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check email", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count > 0 {
		ctx.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}

	// 哈希密码
	// TODO: 实现密码哈希
	// passwordHash := utils.HashPassword(req.Password)
	passwordHash := "hashed_" + req.Password

	// 创建用户
	result, err := c.db.Exec(
		"INSERT INTO users (username, email, password_hash, full_name, role, status) VALUES (?, ?, ?, ?, ?, ?)",
		req.Username, req.Email, passwordHash, req.FullName, "user", "active",
	)
	if err != nil {
		c.logger.Error("Failed to create user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	userID, _ := result.LastInsertId()

	ctx.JSON(http.StatusCreated, gin.H{
		"id":       userID,
		"username": req.Username,
		"email":    req.Email,
		"role":     "user",
		"status":   "active",
	})
}

// GetCurrentUser 获取当前用户信息
func (c *UserController) GetCurrentUser(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var user models.User
	query := "SELECT id, username, email, full_name, phone, role, status, last_login_at, created_at FROM users WHERE id = ?"
	err := c.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.FullName, &user.Phone,
		&user.Role, &user.Status, &user.LastLoginAt, &user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.logger.Error("Failed to query user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// UpdateCurrentUser 更新当前用户信息
func (c *UserController) UpdateCurrentUser(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		Email    string `json:"email"`
		FullName string `json:"full_name"`
		Phone    string `json:"phone"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 如果更新邮箱，检查是否已存在
	if req.Email != "" {
		var count int
		err := c.db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ? AND id != ?", req.Email, userID).Scan(&count)
		if err != nil {
			c.logger.Error("Failed to check email", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		if count > 0 {
			ctx.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
			return
		}
	}

	// 更新用户信息
	_, err := c.db.Exec(
		"UPDATE users SET email = COALESCE(NULLIF(?, ''), email), full_name = COALESCE(NULLIF(?, ''), full_name), phone = COALESCE(NULLIF(?, ''), phone) WHERE id = ?",
		req.Email, req.FullName, req.Phone, userID,
	)
	if err != nil {
		c.logger.Error("Failed to update user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 获取更新后的用户信息
	var user models.User
	query := "SELECT id, username, email, full_name, phone, role, status FROM users WHERE id = ?"
	err = c.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.FullName, &user.Phone, &user.Role, &user.Status,
	)
	if err != nil {
		c.logger.Error("Failed to query updated user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// ChangePassword 修改当前用户密码
func (c *UserController) ChangePassword(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 获取当前密码哈希
	var passwordHash string
	err := c.db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&passwordHash)
	if err != nil {
		c.logger.Error("Failed to get user password", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 验证旧密码
	// TODO: 实现密码验证
	// if !utils.VerifyPassword(passwordHash, req.OldPassword) {
	//     ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid old password"})
	//     return
	// }

	// 哈希新密码
	// TODO: 实现密码哈希
	// newPasswordHash := utils.HashPassword(req.NewPassword)
	newPasswordHash := "hashed_" + req.NewPassword

	// 更新密码
	_, err = c.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newPasswordHash, userID)
	if err != nil {
		c.logger.Error("Failed to update password", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

// ListUsers 获取用户列表（管理员）
func (c *UserController) ListUsers(ctx *gin.Context) {
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

	// 查询用户列表
	rows, err := c.db.Query(
		"SELECT id, username, email, full_name, role, status, created_at FROM users ORDER BY id DESC LIMIT ? OFFSET ?",
		pageSize, offset,
	)
	if err != nil {
		c.logger.Error("Failed to query users", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID, &user.Username, &user.Email, &user.FullName,
			&user.Role, &user.Status, &user.CreatedAt,
		)
		if err != nil {
			c.logger.Error("Failed to scan user row", err)
			continue
		}
		users = append(users, user)
	}

	// 获取总数
	var total int
	err = c.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&total)
	if err != nil {
		c.logger.Error("Failed to count users", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"users": users,
		"pagination": gin.H{
			"page":      page,
			"page_size": pageSize,
			"total":     total,
		},
	})
}

// GetUser 获取指定用户信息（管理员）
func (c *UserController) GetUser(ctx *gin.Context) {
	userID, err := strconv.ParseUint(ctx.Param("id"), 10, 32)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var user models.User
	query := "SELECT id, username, email, full_name, phone, role, status, last_login_at, created_at FROM users WHERE id = ?"
	err = c.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.FullName, &user.Phone,
		&user.Role, &user.Status, &user.LastLoginAt, &user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.logger.Error("Failed to query user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// CreateUser 创建用户（管理员）
func (c *UserController) CreateUser(ctx *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
		FullName string `json:"full_name"`
		Phone    string `json:"phone"`
		Role     string `json:"role" binding:"required"`
		Status   string `json:"status" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 检查角色和状态是否有效
	if req.Role != "admin" && req.Role != "user" && req.Role != "viewer" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role"})
		return
	}
	if req.Status != "active" && req.Status != "inactive" && req.Status != "suspended" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status"})
		return
	}

	// 检查用户名是否已存在
	var count int
	err := c.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", req.Username).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check username", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count > 0 {
		ctx.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	// 检查邮箱是否已存在
	err = c.db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", req.Email).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check email", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count > 0 {
		ctx.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}

	// 哈希密码
	// TODO: 实现密码哈希
	// passwordHash := utils.HashPassword(req.Password)
	passwordHash := "hashed_" + req.Password

	// 创建用户
	result, err := c.db.Exec(
		"INSERT INTO users (username, email, password_hash, full_name, phone, role, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
		req.Username, req.Email, passwordHash, req.FullName, req.Phone, req.Role, req.Status,
	)
	if err != nil {
		c.logger.Error("Failed to create user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	userID, _ := result.LastInsertId()

	ctx.JSON(http.StatusCreated, gin.H{
		"id":       userID,
		"username": req.Username,
		"email":    req.Email,
		"role":     req.Role,
		"status":   req.Status,
	})
}

// UpdateUser 更新用户信息（管理员）
func (c *UserController) UpdateUser(ctx *gin.Context) {
	userID, err := strconv.ParseUint(ctx.Param("id"), 10, 32)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req struct {
		Email    string `json:"email"`
		FullName string `json:"full_name"`
		Phone    string `json:"phone"`
		Role     string `json:"role"`
		Status   string `json:"status"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 检查用户是否存在
	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count == 0 {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 如果更新邮箱，检查是否已存在
	if req.Email != "" {
		err = c.db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ? AND id != ?", req.Email, userID).Scan(&count)
		if err != nil {
			c.logger.Error("Failed to check email", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		if count > 0 {
			ctx.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
			return
		}
	}

	// 检查角色和状态是否有效
	if req.Role != "" && req.Role != "admin" && req.Role != "user" && req.Role != "viewer" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role"})
		return
	}
	if req.Status != "" && req.Status != "active" && req.Status != "inactive" && req.Status != "suspended" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status"})
		return
	}

	// 更新用户信息
	_, err = c.db.Exec(
		"UPDATE users SET email = COALESCE(NULLIF(?, ''), email), full_name = COALESCE(NULLIF(?, ''), full_name), phone = COALESCE(NULLIF(?, ''), phone), role = COALESCE(NULLIF(?, ''), role), status = COALESCE(NULLIF(?, ''), status) WHERE id = ?",
		req.Email, req.FullName, req.Phone, req.Role, req.Status, userID,
	)
	if err != nil {
		c.logger.Error("Failed to update user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// 获取更新后的用户信息
	var user models.User
	query := "SELECT id, username, email, full_name, phone, role, status FROM users WHERE id = ?"
	err = c.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.FullName, &user.Phone, &user.Role, &user.Status,
	)
	if err != nil {
		c.logger.Error("Failed to query updated user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// DeleteUser 删除用户（管理员）
func (c *UserController) DeleteUser(ctx *gin.Context) {
	userID, err := strconv.ParseUint(ctx.Param("id"), 10, 32)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// 检查用户是否存在
	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
	if err != nil {
		c.logger.Error("Failed to check user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if count == 0 {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 删除用户
	_, err = c.db.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		c.logger.Error("Failed to delete user", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// GetSettings 获取系统设置（管理员）
func (c *UserController) GetSettings(ctx *gin.Context) {
	// 查询系统设置
	rows, err := c.db.Query("SELECT category, name, value FROM settings")
	if err != nil {
		c.logger.Error("Failed to query settings", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer rows.Close()

	settings := make(map[string]map[string]string)
	for rows.Next() {
		var category, name, value string
		err := rows.Scan(&category, &name, &value)
		if err != nil {
			c.logger.Error("Failed to scan setting row", err)
			continue
		}

		if _, ok := settings[category]; !ok {
			settings[category] = make(map[string]string)
		}
		settings[category][name] = value
	}

	ctx.JSON(http.StatusOK, settings)
}

// UpdateSettings 更新系统设置（管理员）
func (c *UserController) UpdateSettings(ctx *gin.Context) {
	var req map[string]map[string]string

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
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

	// 更新设置
	stmt, err := tx.Prepare("INSERT INTO settings (category, name, value) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE value = ?")
	if err != nil {
		c.logger.Error("Failed to prepare statement", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer stmt.Close()

	for category, settings := range req {
		for name, value := range settings {
			_, err = stmt.Exec(category, name, value, value)
			if err != nil {
				c.logger.Error("Failed to update setting", err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
				return
			}
		}
	}

	// 提交事务
	err = tx.Commit()
	if err != nil {
		c.logger.Error("Failed to commit transaction", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Settings updated successfully"})
}
