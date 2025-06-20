#!/bin/bash
# 端到端测试脚本
# 用于测试httpsok系统的完整功能流程

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试配置
API_URL="http://localhost:8080/api/v1"
TEST_USER="testuser"
TEST_PASSWORD="Test@123"
TEST_DOMAIN="test.example.com"
AUTH_TOKEN=""

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 测试步骤计数
STEP=1
PASSED=0
FAILED=0

# 测试步骤函数
test_step() {
    local description=$1
    local command=$2
    
    echo -e "\n${YELLOW}步骤 $STEP: $description${NC}"
    STEP=$((STEP+1))
    
    # 执行命令
    eval "$command"
    local status=$?
    
    if [ $status -eq 0 ]; then
        log_info "测试通过"
        PASSED=$((PASSED+1))
    else
        log_error "测试失败 (错误码: $status)"
        FAILED=$((FAILED+1))
    fi
    
    return $status
}

# 等待API服务启动
wait_for_api() {
    log_info "等待API服务启动..."
    local max_retries=10
    local retry_interval=2
    
    for ((i=1; i<=max_retries; i++)); do
        if curl -s "$API_URL/health" > /dev/null; then
            log_info "API服务已启动"
            return 0
        fi
        
        log_warn "API服务未就绪，${retry_interval}秒后重试... ($i/$max_retries)"
        sleep $retry_interval
    done
    
    log_error "API服务启动超时"
    return 1
}

# 用户登录
login() {
    log_info "尝试用户登录..."
    local response=$(curl -s -X POST "$API_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASSWORD\"}")
    
    # 检查响应
    if echo "$response" | grep -q "\"success\":true"; then
        AUTH_TOKEN=$(echo "$response" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
        if [ -n "$AUTH_TOKEN" ]; then
            log_info "登录成功，获取到认证令牌"
            return 0
        else
            log_error "登录成功但未获取到认证令牌"
            return 1
        fi
    else
        log_error "登录失败: $response"
        return 1
    fi
}

# 获取证书列表
get_certificates() {
    log_info "获取证书列表..."
    local response=$(curl -s -X GET "$API_URL/certificates" \
        -H "Authorization: Bearer $AUTH_TOKEN")
    
    # 检查响应
    if echo "$response" | grep -q "\"success\":true"; then
        log_info "获取证书列表成功"
        return 0
    else
        log_error "获取证书列表失败: $response"
        return 1
    fi
}

# 创建证书
create_certificate() {
    log_info "创建测试证书..."
    local response=$(curl -s -X POST "$API_URL/certificates" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d "{\"domain\":\"$TEST_DOMAIN\",\"ca_type\":\"letsencrypt\",\"encryption_type\":\"ECC\",\"notes\":\"E2E测试证书\"}")
    
    # 检查响应
    if echo "$response" | grep -q "\"success\":true"; then
        local cert_id=$(echo "$response" | grep -o '"id":[0-9]*' | cut -d':' -f2)
        log_info "创建证书成功，ID: $cert_id"
        echo "$cert_id"
        return 0
    else
        log_error "创建证书失败: $response"
        return 1
    fi
}

# 获取证书详情
get_certificate_details() {
    local cert_id=$1
    log_info "获取证书详情 (ID: $cert_id)..."
    local response=$(curl -s -X GET "$API_URL/certificates/$cert_id" \
        -H "Authorization: Bearer $AUTH_TOKEN")
    
    # 检查响应
    if echo "$response" | grep -q "\"success\":true"; then
        log_info "获取证书详情成功"
        return 0
    else
        log_error "获取证书详情失败: $response"
        return 1
    fi
}

# 更新证书备注
update_certificate_notes() {
    local cert_id=$1
    log_info "更新证书备注 (ID: $cert_id)..."
    local response=$(curl -s -X PATCH "$API_URL/certificates/$cert_id" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d "{\"notes\":\"E2E测试证书 - 已更新\"}")
    
    # 检查响应
    if echo "$response" | grep -q "\"success\":true"; then
        log_info "更新证书备注成功"
        return 0
    else
        log_error "更新证书备注失败: $response"
        return 1
    fi
}

# 获取服务器列表
get_servers() {
    log_info "获取服务器列表..."
    local response=$(curl -s -X GET "$API_URL/servers" \
        -H "Authorization: Bearer $AUTH_TOKEN")
    
    # 检查响应
    if echo "$response" | grep -q "\"success\":true"; then
        log_info "获取服务器列表成功"
        return 0
    else
        log_error "获取服务器列表失败: $response"
        return 1
    fi
}

# 创建服务器
create_server() {
    log_info "创建测试服务器..."
    local response=$(curl -s -X POST "$API_URL/servers" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d "{\"name\":\"测试服务器\",\"type\":\"nginx\",\"hostname\":\"test.server.local\",\"ip_address\":\"192.168.1.100\",\"os_type\":\"CentOS\",\"os_version\":\"7\",\"version\":\"1.18.0\",\"port\":22,\"username\":\"root\",\"auth_type\":\"password\",\"auth_data\":{\"password\":\"testpassword\"},\"auto_deploy\":true,\"notes\":\"E2E测试服务器\"}")
    
    # 检查响应
    if echo "$response" | grep -q "\"success\":true"; then
        local server_id=$(echo "$response" | grep -o '"id":[0-9]*' | cut -d':' -f2)
        log_info "创建服务器成功，ID: $server_id"
        echo "$server_id"
        return 0
    else
        log_error "创建服务器失败: $response"
        return 1
    fi
}

# 获取监控列表
get_monitors() {
    log_info "获取监控列表..."
    local response=$(curl -s -X GET "$API_URL/monitors" \
        -H "Authorization: Bearer $AUTH_TOKEN")
    
    # 检查响应
    if echo "$response" | grep -q "\"success\":true"; then
        log_info "获取监控列表成功"
        return 0
    else
        log_error "获取监控列表失败: $response"
        return 1
    fi
}

# 创建监控
create_monitor() {
    log_info "创建测试监控..."
    local response=$(curl -s -X POST "$API_URL/monitors" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d "{\"host\":\"$TEST_DOMAIN\",\"port\":443,\"ip_type\":\"domain\",\"check_interval\":1440,\"enabled\":true,\"notes\":\"E2E测试监控\"}")
    
    # 检查响应
    if echo "$response" | grep -q "\"success\":true"; then
        local monitor_id=$(echo "$response" | grep -o '"id":[0-9]*' | cut -d':' -f2)
        log_info "创建监控成功，ID: $monitor_id"
        echo "$monitor_id"
        return 0
    else
        log_error "创建监控失败: $response"
        return 1
    fi
}

# 删除测试数据
cleanup() {
    log_info "清理测试数据..."
    
    # 删除监控
    if [ -n "$MONITOR_ID" ]; then
        curl -s -X DELETE "$API_URL/monitors/$MONITOR_ID" \
            -H "Authorization: Bearer $AUTH_TOKEN" > /dev/null
        log_info "删除监控 (ID: $MONITOR_ID)"
    fi
    
    # 删除服务器
    if [ -n "$SERVER_ID" ]; then
        curl -s -X DELETE "$API_URL/servers/$SERVER_ID" \
            -H "Authorization: Bearer $AUTH_TOKEN" > /dev/null
        log_info "删除服务器 (ID: $SERVER_ID)"
    fi
    
    # 删除证书
    if [ -n "$CERT_ID" ]; then
        curl -s -X DELETE "$API_URL/certificates/$CERT_ID" \
            -H "Authorization: Bearer $AUTH_TOKEN" > /dev/null
        log_info "删除证书 (ID: $CERT_ID)"
    fi
}

# 主测试流程
main() {
    echo -e "${GREEN}===== httpsok系统端到端测试 =====${NC}"
    echo "开始时间: $(date)"
    
    # 等待API服务
    test_step "等待API服务启动" "wait_for_api"
    if [ $? -ne 0 ]; then
        log_error "API服务未就绪，测试终止"
        exit 1
    fi
    
    # 用户认证测试
    test_step "用户登录" "login"
    if [ $? -ne 0 ]; then
        log_error "用户认证失败，测试终止"
        exit 1
    fi
    
    # 证书管理测试
    test_step "获取证书列表" "get_certificates"
    
    CERT_ID=$(test_step "创建证书" "create_certificate")
    
    if [ -n "$CERT_ID" ]; then
        test_step "获取证书详情" "get_certificate_details $CERT_ID"
        test_step "更新证书备注" "update_certificate_notes $CERT_ID"
    fi
    
    # 服务器管理测试
    test_step "获取服务器列表" "get_servers"
    
    SERVER_ID=$(test_step "创建服务器" "create_server")
    
    # 监控管理测试
    test_step "获取监控列表" "get_monitors"
    
    MONITOR_ID=$(test_step "创建监控" "create_monitor")
    
    # 清理测试数据
    cleanup
    
    # 测试结果统计
    echo -e "\n${GREEN}===== 测试结果统计 =====${NC}"
    echo "总测试步骤: $((PASSED + FAILED))"
    echo -e "${GREEN}通过: $PASSED${NC}"
    echo -e "${RED}失败: $FAILED${NC}"
    echo "结束时间: $(date)"
    
    if [ $FAILED -eq 0 ]; then
        echo -e "\n${GREEN}所有测试通过!${NC}"
        exit 0
    else
        echo -e "\n${RED}测试存在失败项，请检查日志!${NC}"
        exit 1
    fi
}

# 执行主测试流程
main
