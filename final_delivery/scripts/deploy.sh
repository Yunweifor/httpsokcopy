#!/bin/bash
# httpsok系统部署脚本
# 用于自动化部署httpsok系统

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置参数
APP_NAME="httpsok"
APP_VERSION="1.0.0"
APP_PORT=8080
DB_NAME="httpsok"
DB_USER="httpsok"
DB_PORT=3306
LOG_DIR="/var/log/httpsok"
CONFIG_DIR="/etc/httpsok"
DATA_DIR="/var/lib/httpsok"
SYSTEMD_SERVICE="/etc/systemd/system/httpsok.service"

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}==== $1 ====${NC}"
}

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "此脚本需要root权限运行，请使用sudo或以root用户运行"
    fi
}

# 检查系统环境
check_system() {
    log_step "检查系统环境"
    
    # 检查操作系统
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        log_info "检测到操作系统: $OS $VER"
    else
        log_warn "无法确定操作系统类型，可能导致安装问题"
    fi
    
    # 检查必要工具
    for cmd in curl wget systemctl mysql go; do
        if ! command -v $cmd &> /dev/null; then
            log_warn "未找到命令: $cmd，将尝试安装"
        else
            log_info "检测到命令: $cmd $(command -v $cmd)"
        fi
    done
}

# 安装依赖
install_dependencies() {
    log_step "安装依赖"
    
    # 根据不同的操作系统安装依赖（不再安装系统自带golang）
    if [ -f /etc/debian_version ]; then
        log_info "使用apt安装依赖..."
        apt-get update
        apt-get install -y curl wget git mysql-server
    elif [ -f /etc/redhat-release ]; then
        log_info "使用yum安装依赖..."
        yum -y update
        yum -y install curl wget git mysql-server
    else
        log_warn "未知的操作系统，请手动安装依赖: curl wget git mysql-server"
    fi

    # 安装Go 1.21.13（仅当当前Go版本不满足要求时）
    REQUIRED_GO_VERSION=1.21
    CURRENT_GO_VERSION="$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//')"
    if [ -z "$CURRENT_GO_VERSION" ]; then
        INSTALL_GO=1
    else
        MAJOR_MINOR=$(echo $CURRENT_GO_VERSION | awk -F. '{print $1 "." $2}')
        if [ "$(echo -e "$MAJOR_MINOR\n$REQUIRED_GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_GO_VERSION" ]; then
            INSTALL_GO=1
        else
            INSTALL_GO=0
        fi
    fi
    if [ "$INSTALL_GO" = "1" ]; then
        GO_VERSION=1.21.13
        GO_TARBALL=go$GO_VERSION.linux-amd64.tar.gz
        log_info "下载并安装Go $GO_VERSION ..."
        wget -q https://go.dev/dl/$GO_TARBALL -O /tmp/$GO_TARBALL
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/$GO_TARBALL
        export PATH=/usr/local/go/bin:$PATH
        if ! grep -q '/usr/local/go/bin' /etc/profile; then
            echo 'export PATH=/usr/local/go/bin:$PATH' >> /etc/profile
        fi
        go version
    else
        log_info "当前Go版本($CURRENT_GO_VERSION)已满足要求，无需重新安装。"
    fi
    
    log_info "依赖安装完成"
}

# 配置MySQL
setup_mysql() {
    log_step "配置MySQL"
    
    # 确保MySQL服务启动
    log_info "启动MySQL服务..."
    systemctl enable mysql
    systemctl start mysql
    
    # 等待MySQL启动
    for i in {1..30}; do
        if mysqladmin ping -h localhost --silent; then
            break
        fi
        echo -n "."
        sleep 1
    done
    echo ""
    
    if ! mysqladmin ping -h localhost --silent; then
        log_error "MySQL服务启动失败"
    fi
    
    log_info "MySQL服务已启动"
    
    # 创建数据库和用户
    log_info "创建数据库和用户..."
    
    # 生成随机密码
    DB_PASS=$(openssl rand -base64 12)
    
    # 创建数据库和用户
    mysql -e "CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    
    log_info "数据库和用户创建完成"
    
    # 导入数据库结构
    log_info "导入数据库结构..."
    mysql $DB_NAME < ./scripts/schema.sql
    log_info "数据库结构导入完成"
}

# 编译应用
build_app() {
    log_step "编译应用"
    
    log_info "编译后端服务..."
    go mod tidy
    cd ./cmd
    go build -o $APP_NAME
    if [ $? -ne 0 ]; then
        log_error "编译失败"
    fi
    cd ..
    
    log_info "编译前端资源..."
    # 这里可以添加前端构建命令，如npm run build等
    
    log_info "应用编译完成"
}

# 创建目录结构
create_directories() {
    log_step "创建目录结构"
    
    mkdir -p $LOG_DIR
    mkdir -p $CONFIG_DIR
    mkdir -p $DATA_DIR
    mkdir -p $DATA_DIR/certs
    
    log_info "目录结构创建完成"
}

# 配置应用
configure_app() {
    log_step "配置应用"
    
    # 创建配置目录
    mkdir -p /opt/httpsok/configs
    
    # 复制config.json到部署目录
    log_info "复制config.json配置文件..."
    cp ./configs/config.json /opt/httpsok/configs/config.json
    
    # 复制acme.sh
    log_info "配置acme.sh..."
    cp ./scripts/acme.sh /usr/local/bin/
    chmod +x /usr/local/bin/acme.sh
    
    log_info "应用配置完成"
}

# 安装服务
install_service() {
    log_step "安装系统服务"
    
    # 创建systemd服务文件
    log_info "创建systemd服务文件..."
    cat > $SYSTEMD_SERVICE << EOF
[Unit]
Description=httpsok SSL Certificate Management System
After=network.target mysql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/httpsok
ExecStart=/opt/httpsok/httpsok
Restart=on-failure
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=httpsok

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载systemd
    systemctl daemon-reload
    
    log_info "系统服务安装完成"
}

# 部署应用
deploy_app() {
    log_step "部署应用"
    
    # 创建应用目录
    mkdir -p /opt/httpsok
    
    # 复制应用文件
    log_info "复制应用文件..."
    cp ./cmd/$APP_NAME /opt/httpsok/
    cp -r ./web /opt/httpsok/
    
    # 设置权限
    chmod +x /opt/httpsok/$APP_NAME
    
    log_info "应用部署完成"
}

# 启动服务
start_service() {
    log_step "启动服务"
    
    systemctl enable httpsok
    systemctl start httpsok
    
    # 检查服务状态
    sleep 3
    if systemctl is-active --quiet httpsok; then
        log_info "httpsok服务已成功启动"
    else
        log_error "httpsok服务启动失败，请检查日志"
    fi
}

# 显示安装信息
show_info() {
    log_step "安装完成"
    
    # 动态读取端口号
    SERVER_PORT=$(grep -o '"port"[ ]*:[ ]*[0-9]*' /opt/httpsok/configs/config.json | head -1 | grep -o '[0-9]\+')
    if [ -z "$SERVER_PORT" ]; then
        SERVER_PORT=8080
    fi

    echo -e "${GREEN}httpsok系统已成功安装!${NC}"
    echo ""
    echo "Web控制台: http://localhost:$SERVER_PORT"
    echo "API接口: http://localhost:$SERVER_PORT/api/v1"
    echo "配置文件: $CONFIG_DIR/config.json"
    echo "日志目录: $LOG_DIR"
    echo "数据目录: $DATA_DIR"
    echo ""
    echo "数据库信息:"
    echo "  数据库名: $DB_NAME"
    echo "  用户名: $DB_USER"
    echo "  密码: $DB_PASS"
    echo ""
    echo "服务管理命令:"
    echo "  启动: systemctl start httpsok"
    echo "  停止: systemctl stop httpsok"
    echo "  重启: systemctl restart httpsok"
    echo "  状态: systemctl status httpsok"
    echo ""
    echo -e "${YELLOW}请妥善保存以上信息，特别是数据库密码!${NC}"
}

# 主函数
main() {
    echo -e "${BLUE}===== httpsok系统部署脚本 =====${NC}"
    echo "版本: $APP_VERSION"
    echo "开始时间: $(date)"
    echo ""
    
    # 检查root权限
    check_root
    
    # 检查系统环境
    check_system
    
    # 安装依赖
    install_dependencies
    
    # 配置MySQL
    setup_mysql
    
    # 编译应用
    build_app
    
    # 创建目录结构
    create_directories
    
    # 配置应用
    configure_app
    
    # 安装服务
    install_service
    
    # 部署应用
    deploy_app
    
    # 启动服务
    start_service
    
    # 显示安装信息
    show_info
    
    echo ""
    echo "结束时间: $(date)"
}

# 执行主函数
main
