# httpsok系统部署指南

## 1. 系统要求

### 1.1 硬件要求

- **CPU**：2核心或更高
- **内存**：4GB或更高
- **磁盘空间**：20GB或更高
- **网络**：可访问互联网

### 1.2 软件要求

- **操作系统**：
  - Ubuntu 18.04/20.04/22.04 LTS
  - CentOS 7/8
  - Debian 10/11
  
- **依赖软件**：
  - Go 1.16+
  - MySQL 5.7+
  - Nginx（可选，用于反向代理）
  - Git
  - curl
  - wget

## 2. 安装方法

httpsok系统提供了三种安装方法：

1. 自动安装脚本（推荐）
2. 手动安装
3. Docker安装

### 2.1 自动安装脚本

自动安装脚本是最简单的安装方法，适合大多数用户。

#### 2.1.1 下载安装脚本

```bash
curl -O https://example.com/httpsok/install.sh
chmod +x install.sh
```

#### 2.1.2 运行安装脚本

```bash
sudo ./install.sh
```

安装脚本会自动检查系统环境，安装依赖，配置数据库，编译应用，并启动服务。

#### 2.1.3 安装选项

安装脚本支持以下选项：

```bash
# 指定安装目录
sudo ./install.sh --install-dir=/opt/httpsok

# 指定数据库配置
sudo ./install.sh --db-host=localhost --db-port=3306 --db-user=httpsok --db-pass=password

# 指定应用端口
sudo ./install.sh --app-port=8080

# 安装开发版本
sudo ./install.sh --dev
```

### 2.2 手动安装

如果您需要更多的定制化安装，可以选择手动安装。

#### 2.2.1 安装依赖

**Ubuntu/Debian**:

```bash
# 更新软件包列表
sudo apt update

# 安装依赖
sudo apt install -y git curl wget mysql-server golang-go
```

**CentOS/RHEL**:

```bash
# 更新软件包列表
sudo yum update

# 安装依赖
sudo yum install -y git curl wget mysql-server golang
```

#### 2.2.2 配置MySQL

```bash
# 启动MySQL服务
sudo systemctl start mysql
sudo systemctl enable mysql

# 创建数据库和用户
sudo mysql -e "CREATE DATABASE httpsok CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
sudo mysql -e "CREATE USER 'httpsok'@'localhost' IDENTIFIED BY 'your_password';"
sudo mysql -e "GRANT ALL PRIVILEGES ON httpsok.* TO 'httpsok'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# 导入数据库结构
sudo mysql httpsok < /path/to/httpsok/scripts/schema.sql
```

#### 2.2.3 下载源代码

```bash
# 克隆代码仓库
git clone https://github.com/example/httpsok.git
cd httpsok
```

#### 2.2.4 编译应用

```bash
# 进入cmd目录
cd cmd

# 编译应用
go build -o httpsok

# 返回上级目录
cd ..
```

#### 2.2.5 配置应用

```bash
# 创建配置目录
sudo mkdir -p /etc/httpsok

# 创建配置文件
sudo tee /etc/httpsok/config.yaml > /dev/null << EOF
app:
  name: httpsok
  version: 1.0.0
  port: 8080
  log_dir: /var/log/httpsok
  data_dir: /var/lib/httpsok

database:
  driver: mysql
  host: localhost
  port: 3306
  name: httpsok
  user: httpsok
  password: your_password

acme:
  path: /usr/local/bin/acme.sh
  default_ca: letsencrypt
  default_encryption: ECC
EOF

# 创建日志和数据目录
sudo mkdir -p /var/log/httpsok
sudo mkdir -p /var/lib/httpsok
sudo mkdir -p /var/lib/httpsok/certs
```

#### 2.2.6 安装acme.sh

```bash
# 下载acme.sh
curl https://get.acme.sh | sh

# 复制acme.sh到系统目录
sudo cp ~/.acme.sh/acme.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/acme.sh
```

#### 2.2.7 创建系统服务

```bash
# 创建服务文件
sudo tee /etc/systemd/system/httpsok.service > /dev/null << EOF
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
sudo systemctl daemon-reload
```

#### 2.2.8 部署应用

```bash
# 创建应用目录
sudo mkdir -p /opt/httpsok

# 复制应用文件
sudo cp ./cmd/httpsok /opt/httpsok/
sudo cp -r ./web /opt/httpsok/

# 设置权限
sudo chmod +x /opt/httpsok/httpsok
```

#### 2.2.9 启动服务

```bash
# 启动服务
sudo systemctl start httpsok

# 设置开机自启
sudo systemctl enable httpsok

# 检查服务状态
sudo systemctl status httpsok
```

### 2.3 Docker安装

如果您熟悉Docker，可以使用Docker安装httpsok系统。

#### 2.3.1 安装Docker

**Ubuntu/Debian**:

```bash
# 安装Docker
sudo apt update
sudo apt install -y docker.io docker-compose

# 启动Docker服务
sudo systemctl start docker
sudo systemctl enable docker
```

**CentOS/RHEL**:

```bash
# 安装Docker
sudo yum install -y docker docker-compose

# 启动Docker服务
sudo systemctl start docker
sudo systemctl enable docker
```

#### 2.3.2 创建Docker Compose配置

```bash
# 创建项目目录
mkdir -p ~/httpsok
cd ~/httpsok

# 创建docker-compose.yml文件
tee docker-compose.yml > /dev/null << EOF
version: '3'

services:
  db:
    image: mysql:5.7
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: httpsok
      MYSQL_USER: httpsok
      MYSQL_PASSWORD: password
    volumes:
      - ./mysql:/var/lib/mysql
      - ./scripts/schema.sql:/docker-entrypoint-initdb.d/schema.sql
    networks:
      - httpsok-network

  app:
    image: example/httpsok:latest
    restart: always
    depends_on:
      - db
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/httpsok
      - ./logs:/var/log/httpsok
      - ./data:/var/lib/httpsok
    networks:
      - httpsok-network

networks:
  httpsok-network:
EOF

# 创建配置目录
mkdir -p config logs data

# 创建配置文件
tee config/config.yaml > /dev/null << EOF
app:
  name: httpsok
  version: 1.0.0
  port: 8080
  log_dir: /var/log/httpsok
  data_dir: /var/lib/httpsok

database:
  driver: mysql
  host: db
  port: 3306
  name: httpsok
  user: httpsok
  password: password

acme:
  path: /usr/local/bin/acme.sh
  default_ca: letsencrypt
  default_encryption: ECC
EOF
```

#### 2.3.3 启动Docker容器

```bash
# 下载Docker镜像
docker pull example/httpsok:latest

# 启动容器
docker-compose up -d

# 检查容器状态
docker-compose ps
```

## 3. 配置说明

### 3.1 配置文件

httpsok系统的主配置文件是`config.yaml`，位于`/etc/httpsok/`目录下。配置文件包含以下几个部分：

#### 3.1.1 应用配置

```yaml
app:
  name: httpsok                # 应用名称
  version: 1.0.0               # 应用版本
  port: 8080                   # 应用端口
  log_dir: /var/log/httpsok    # 日志目录
  data_dir: /var/lib/httpsok   # 数据目录
```

#### 3.1.2 数据库配置

```yaml
database:
  driver: mysql                # 数据库驱动
  host: localhost              # 数据库主机
  port: 3306                   # 数据库端口
  name: httpsok                # 数据库名称
  user: httpsok                # 数据库用户
  password: your_password      # 数据库密码
```

#### 3.1.3 acme.sh配置

```yaml
acme:
  path: /usr/local/bin/acme.sh  # acme.sh路径
  default_ca: letsencrypt        # 默认CA
  default_encryption: ECC        # 默认加密类型
```

#### 3.1.4 日志配置

```yaml
log:
  level: info                   # 日志级别（debug, info, warn, error）
  format: json                  # 日志格式（text, json）
  output: file                  # 日志输出（console, file, both）
  max_size: 100                 # 单个日志文件最大大小（MB）
  max_age: 30                   # 日志文件保留天数
  max_backups: 10               # 最大日志文件数量
```

#### 3.1.5 安全配置

```yaml
security:
  jwt_secret: your_jwt_secret   # JWT密钥
  jwt_expiry: 86400             # JWT过期时间（秒）
  password_salt: your_salt      # 密码盐值
  enable_csrf: true             # 是否启用CSRF保护
  cors_allowed_origins:         # CORS允许的源
    - http://localhost:8080
    - https://example.com
```

### 3.2 环境变量

除了配置文件，httpsok系统还支持通过环境变量进行配置。环境变量的优先级高于配置文件。

```bash
# 应用配置
export HTTPSOK_APP_PORT=8080
export HTTPSOK_LOG_DIR=/var/log/httpsok
export HTTPSOK_DATA_DIR=/var/lib/httpsok

# 数据库配置
export HTTPSOK_DB_HOST=localhost
export HTTPSOK_DB_PORT=3306
export HTTPSOK_DB_NAME=httpsok
export HTTPSOK_DB_USER=httpsok
export HTTPSOK_DB_PASSWORD=your_password

# acme.sh配置
export HTTPSOK_ACME_PATH=/usr/local/bin/acme.sh
export HTTPSOK_ACME_DEFAULT_CA=letsencrypt
export HTTPSOK_ACME_DEFAULT_ENCRYPTION=ECC

# 安全配置
export HTTPSOK_JWT_SECRET=your_jwt_secret
export HTTPSOK_JWT_EXPIRY=86400
```

## 4. 升级指南

### 4.1 使用自动升级脚本

httpsok系统提供了自动升级脚本，可以轻松升级到最新版本。

```bash
# 下载升级脚本
curl -O https://example.com/httpsok/upgrade.sh
chmod +x upgrade.sh

# 运行升级脚本
sudo ./upgrade.sh
```

### 4.2 手动升级

如果您需要更多的控制，可以选择手动升级。

```bash
# 停止服务
sudo systemctl stop httpsok

# 备份数据
sudo cp -r /opt/httpsok /opt/httpsok.bak
sudo mysqldump -u httpsok -p httpsok > httpsok_backup.sql

# 下载新版本
git clone https://github.com/example/httpsok.git
cd httpsok

# 编译应用
cd cmd
go build -o httpsok
cd ..

# 更新应用
sudo cp ./cmd/httpsok /opt/httpsok/
sudo cp -r ./web /opt/httpsok/

# 更新数据库结构
sudo mysql httpsok < ./scripts/upgrade.sql

# 启动服务
sudo systemctl start httpsok
```

## 5. 常见问题

### 5.1 安装问题

#### 5.1.1 依赖安装失败

**问题**：安装依赖时出现错误。

**解决方案**：

1. 确保系统已更新：
   ```bash
   sudo apt update  # Ubuntu/Debian
   sudo yum update  # CentOS/RHEL
   ```

2. 检查网络连接：
   ```bash
   ping google.com
   ```

3. 手动安装依赖：
   ```bash
   sudo apt install -y git curl wget mysql-server golang-go  # Ubuntu/Debian
   sudo yum install -y git curl wget mysql-server golang     # CentOS/RHEL
   ```

#### 5.1.2 MySQL启动失败

**问题**：MySQL服务无法启动。

**解决方案**：

1. 检查MySQL状态：
   ```bash
   sudo systemctl status mysql
   ```

2. 检查错误日志：
   ```bash
   sudo tail -n 100 /var/log/mysql/error.log
   ```

3. 重置MySQL：
   ```bash
   sudo systemctl stop mysql
   sudo rm -rf /var/lib/mysql/ib_logfile*
   sudo systemctl start mysql
   ```

#### 5.1.3 端口冲突

**问题**：应用无法启动，端口被占用。

**解决方案**：

1. 检查端口占用：
   ```bash
   sudo netstat -tulpn | grep 8080
   ```

2. 终止占用端口的进程：
   ```bash
   sudo kill -9 <PID>
   ```

3. 修改应用端口：
   ```bash
   sudo nano /etc/httpsok/config.yaml
   # 修改app.port值
   ```

### 5.2 配置问题

#### 5.2.1 数据库连接失败

**问题**：应用无法连接到数据库。

**解决方案**：

1. 检查数据库服务是否运行：
   ```bash
   sudo systemctl status mysql
   ```

2. 检查数据库连接配置：
   ```bash
   sudo nano /etc/httpsok/config.yaml
   # 检查database部分的配置
   ```

3. 测试数据库连接：
   ```bash
   mysql -u httpsok -p -h localhost httpsok
   ```

#### 5.2.2 acme.sh路径错误

**问题**：应用无法找到acme.sh。

**解决方案**：

1. 检查acme.sh是否安装：
   ```bash
   which acme.sh
   ```

2. 安装acme.sh：
   ```bash
   curl https://get.acme.sh | sh
   ```

3. 更新配置文件中的acme.sh路径：
   ```bash
   sudo nano /etc/httpsok/config.yaml
   # 修改acme.path值
   ```

### 5.3 运行问题

#### 5.3.1 服务无法启动

**问题**：httpsok服务无法启动。

**解决方案**：

1. 检查服务状态：
   ```bash
   sudo systemctl status httpsok
   ```

2. 检查日志：
   ```bash
   sudo journalctl -u httpsok
   ```

3. 检查应用日志：
   ```bash
   sudo tail -n 100 /var/log/httpsok/httpsok.log
   ```

4. 手动启动应用检查错误：
   ```bash
   cd /opt/httpsok
   sudo ./httpsok
   ```

#### 5.3.2 证书申请失败

**问题**：无法申请SSL证书。

**解决方案**：

1. 检查DNS记录是否正确配置：
   ```bash
   dig _acme-challenge.example.com TXT
   ```

2. 检查acme.sh是否可以正常工作：
   ```bash
   sudo acme.sh --issue --test -d example.com --dns
   ```

3. 检查应用日志中的错误信息：
   ```bash
   sudo tail -n 100 /var/log/httpsok/httpsok.log
   ```

#### 5.3.3 证书部署失败

**问题**：证书无法部署到服务器。

**解决方案**：

1. 检查服务器连接信息是否正确：
   ```bash
   ssh username@hostname -p port
   ```

2. 检查服务器上的目标路径是否存在：
   ```bash
   ssh username@hostname "ls -la /path/to/cert/directory"
   ```

3. 检查服务器上的权限：
   ```bash
   ssh username@hostname "sudo -l"
   ```

4. 检查应用日志中的错误信息：
   ```bash
   sudo tail -n 100 /var/log/httpsok/httpsok.log
   ```

## 6. 性能优化

### 6.1 数据库优化

#### 6.1.1 索引优化

httpsok系统的数据库已经包含了基本的索引，但您可以根据实际使用情况添加更多索引：

```sql
-- 为证书表添加复合索引
ALTER TABLE certificates ADD INDEX idx_user_domain (user_id, domain);

-- 为监控表添加复合索引
ALTER TABLE monitors ADD INDEX idx_user_status (user_id, status);
```

#### 6.1.2 配置优化

修改MySQL配置以提高性能：

```bash
sudo nano /etc/mysql/my.cnf
```

添加以下配置：

```ini
[mysqld]
# 缓冲池大小
innodb_buffer_pool_size = 1G

# 日志文件大小
innodb_log_file_size = 256M

# 查询缓存
query_cache_size = 64M
query_cache_type = 1

# 连接数
max_connections = 200
```

重启MySQL服务：

```bash
sudo systemctl restart mysql
```

### 6.2 应用优化

#### 6.2.1 并发设置

修改应用配置以提高并发处理能力：

```bash
sudo nano /etc/httpsok/config.yaml
```

添加以下配置：

```yaml
server:
  max_workers: 10           # 最大工作线程数
  connection_timeout: 30    # 连接超时时间（秒）
  read_timeout: 30          # 读取超时时间（秒）
  write_timeout: 30         # 写入超时时间（秒）
  idle_timeout: 60          # 空闲超时时间（秒）
```

#### 6.2.2 缓存设置

添加缓存配置以提高响应速度：

```yaml
cache:
  enabled: true             # 启用缓存
  type: memory              # 缓存类型（memory, redis）
  ttl: 300                  # 缓存过期时间（秒）
  max_size: 1000            # 最大缓存条目数
```

### 6.3 Web服务器优化

如果您使用Nginx作为反向代理，可以进行以下优化：

```bash
sudo nano /etc/nginx/sites-available/httpsok
```

配置示例：

```nginx
server {
    listen 80;
    server_name example.com;
    
    # 重定向到HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name example.com;
    
    # SSL配置
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # 反向代理
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # 超时设置
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # 缓冲设置
        proxy_buffer_size 16k;
        proxy_buffers 4 32k;
        proxy_busy_buffers_size 64k;
    }
    
    # 静态文件
    location /assets/ {
        alias /opt/httpsok/web/assets/;
        expires 7d;
        add_header Cache-Control "public";
    }
    
    # Gzip压缩
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    gzip_min_length 1000;
    gzip_comp_level 6;
}
```

重新加载Nginx配置：

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 7. 备份与恢复

### 7.1 数据备份

#### 7.1.1 数据库备份

创建数据库备份脚本：

```bash
sudo nano /opt/httpsok/scripts/backup_db.sh
```

脚本内容：

```bash
#!/bin/bash

# 配置
BACKUP_DIR="/var/backups/httpsok"
DB_NAME="httpsok"
DB_USER="httpsok"
DB_PASS="your_password"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/httpsok_db_$DATE.sql.gz"

# 创建备份目录
mkdir -p $BACKUP_DIR

# 备份数据库
mysqldump -u $DB_USER -p$DB_PASS $DB_NAME | gzip > $BACKUP_FILE

# 保留最近30天的备份
find $BACKUP_DIR -name "httpsok_db_*.sql.gz" -type f -mtime +30 -delete

echo "Database backup completed: $BACKUP_FILE"
```

设置执行权限：

```bash
sudo chmod +x /opt/httpsok/scripts/backup_db.sh
```

添加到crontab：

```bash
sudo crontab -e
```

添加以下内容：

```
0 2 * * * /opt/httpsok/scripts/backup_db.sh >> /var/log/httpsok/backup.log 2>&1
```

#### 7.1.2 证书备份

创建证书备份脚本：

```bash
sudo nano /opt/httpsok/scripts/backup_certs.sh
```

脚本内容：

```bash
#!/bin/bash

# 配置
BACKUP_DIR="/var/backups/httpsok"
CERTS_DIR="/var/lib/httpsok/certs"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/httpsok_certs_$DATE.tar.gz"

# 创建备份目录
mkdir -p $BACKUP_DIR

# 备份证书
tar -czf $BACKUP_FILE $CERTS_DIR

# 保留最近30天的备份
find $BACKUP_DIR -name "httpsok_certs_*.tar.gz" -type f -mtime +30 -delete

echo "Certificate backup completed: $BACKUP_FILE"
```

设置执行权限：

```bash
sudo chmod +x /opt/httpsok/scripts/backup_certs.sh
```

添加到crontab：

```bash
sudo crontab -e
```

添加以下内容：

```
0 3 * * * /opt/httpsok/scripts/backup_certs.sh >> /var/log/httpsok/backup.log 2>&1
```

### 7.2 数据恢复

#### 7.2.1 数据库恢复

```bash
# 停止服务
sudo systemctl stop httpsok

# 恢复数据库
gunzip -c /var/backups/httpsok/httpsok_db_YYYYMMDD_HHMMSS.sql.gz | mysql -u httpsok -p httpsok

# 启动服务
sudo systemctl start httpsok
```

#### 7.2.2 证书恢复

```bash
# 停止服务
sudo systemctl stop httpsok

# 恢复证书
sudo tar -xzf /var/backups/httpsok/httpsok_certs_YYYYMMDD_HHMMSS.tar.gz -C /

# 启动服务
sudo systemctl start httpsok
```

## 8. 安全加固

### 8.1 系统安全

#### 8.1.1 防火墙配置

配置防火墙只允许必要的端口：

```bash
# Ubuntu/Debian (UFW)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8080/tcp
sudo ufw enable

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

#### 8.1.2 系统更新

定期更新系统：

```bash
# Ubuntu/Debian
sudo apt update
sudo apt upgrade -y

# CentOS/RHEL
sudo yum update -y
```

#### 8.1.3 用户权限

创建专用用户运行应用：

```bash
# 创建用户
sudo useradd -r -s /bin/false httpsok

# 设置目录权限
sudo chown -R httpsok:httpsok /opt/httpsok
sudo chown -R httpsok:httpsok /var/log/httpsok
sudo chown -R httpsok:httpsok /var/lib/httpsok

# 修改服务文件
sudo nano /etc/systemd/system/httpsok.service
# 将User=root改为User=httpsok

# 重新加载systemd
sudo systemctl daemon-reload
```

### 8.2 应用安全

#### 8.2.1 HTTPS配置

配置应用使用HTTPS：

```bash
sudo nano /etc/httpsok/config.yaml
```

添加以下配置：

```yaml
server:
  use_tls: true
  cert_file: /path/to/cert.pem
  key_file: /path/to/key.pem
```

#### 8.2.2 密码策略

配置强密码策略：

```yaml
security:
  password_policy:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_number: true
    require_special: true
    max_age: 90
    history_count: 5
```

#### 8.2.3 访问控制

配置IP访问限制：

```yaml
security:
  ip_whitelist:
    - 192.168.1.0/24
    - 10.0.0.0/8
  rate_limit:
    enabled: true
    requests_per_minute: 60
```

### 8.3 数据安全

#### 8.3.1 数据加密

配置敏感数据加密：

```yaml
security:
  encryption:
    key: your_encryption_key
    algorithm: AES-256-GCM
```

#### 8.3.2 MySQL安全

加固MySQL安全：

```bash
# 运行MySQL安全脚本
sudo mysql_secure_installation

# 配置MySQL只监听本地连接
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
# 添加或修改：bind-address = 127.0.0.1
```

## 9. 监控与日志

### 9.1 日志配置

#### 9.1.1 应用日志

配置应用日志：

```yaml
log:
  level: info
  format: json
  output: file
  file: /var/log/httpsok/httpsok.log
  max_size: 100
  max_age: 30
  max_backups: 10
```

#### 9.1.2 系统日志

配置系统日志：

```bash
# 创建rsyslog配置
sudo nano /etc/rsyslog.d/httpsok.conf
```

添加以下内容：

```
if $programname == 'httpsok' then /var/log/httpsok/system.log
& stop
```

重启rsyslog：

```bash
sudo systemctl restart rsyslog
```

### 9.2 监控配置

#### 9.2.1 系统监控

使用Prometheus和Node Exporter监控系统：

```bash
# 安装Node Exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.3.1/node_exporter-1.3.1.linux-amd64.tar.gz
tar xvfz node_exporter-1.3.1.linux-amd64.tar.gz
sudo cp node_exporter-1.3.1.linux-amd64/node_exporter /usr/local/bin/
sudo useradd -rs /bin/false node_exporter

# 创建systemd服务
sudo nano /etc/systemd/system/node_exporter.service
```

服务文件内容：

```ini
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl enable node_exporter
```

#### 9.2.2 应用监控

配置应用暴露Prometheus指标：

```yaml
monitoring:
  prometheus:
    enabled: true
    path: /metrics
```

## 10. 故障排除

### 10.1 常见错误

#### 10.1.1 服务启动失败

**问题**：服务无法启动。

**排查步骤**：

1. 检查服务状态：
   ```bash
   sudo systemctl status httpsok
   ```

2. 检查日志：
   ```bash
   sudo journalctl -u httpsok
   sudo tail -n 100 /var/log/httpsok/httpsok.log
   ```

3. 检查配置文件：
   ```bash
   sudo nano /etc/httpsok/config.yaml
   ```

4. 检查权限：
   ```bash
   ls -la /opt/httpsok
   ls -la /var/log/httpsok
   ls -la /var/lib/httpsok
   ```

#### 10.1.2 数据库连接错误

**问题**：应用无法连接到数据库。

**排查步骤**：

1. 检查MySQL服务状态：
   ```bash
   sudo systemctl status mysql
   ```

2. 检查数据库连接配置：
   ```bash
   sudo nano /etc/httpsok/config.yaml
   ```

3. 测试数据库连接：
   ```bash
   mysql -u httpsok -p -h localhost httpsok
   ```

4. 检查数据库日志：
   ```bash
   sudo tail -n 100 /var/log/mysql/error.log
   ```

#### 10.1.3 证书操作失败

**问题**：证书申请或部署失败。

**排查步骤**：

1. 检查acme.sh是否正常工作：
   ```bash
   sudo acme.sh --version
   ```

2. 检查DNS记录：
   ```bash
   dig _acme-challenge.example.com TXT
   ```

3. 检查服务器连接：
   ```bash
   ssh username@hostname -p port
   ```

4. 检查应用日志：
   ```bash
   sudo tail -n 100 /var/log/httpsok/httpsok.log
   ```

### 10.2 诊断工具

#### 10.2.1 系统诊断

```bash
# 检查系统资源
top
free -h
df -h

# 检查网络连接
netstat -tulpn
ss -tulpn

# 检查进程
ps aux | grep httpsok
```

#### 10.2.2 应用诊断

```bash
# 检查应用状态
curl http://localhost:8080/api/v1/health

# 检查应用指标
curl http://localhost:8080/metrics

# 检查应用日志
sudo tail -f /var/log/httpsok/httpsok.log
```

#### 10.2.3 数据库诊断

```bash
# 检查数据库状态
mysqladmin -u httpsok -p status

# 检查数据库表
mysql -u httpsok -p -e "SHOW TABLES FROM httpsok;"

# 检查数据库连接
mysql -u httpsok -p -e "SHOW PROCESSLIST;"
```

### 10.3 常见问题解决

#### 10.3.1 重置管理员密码

```bash
# 连接到数据库
mysql -u httpsok -p httpsok

# 更新管理员密码（密码为"admin123"的bcrypt哈希）
mysql> UPDATE users SET password='$2a$10$JwZpJMmzDp8Kg7GJZ9J6B.4QMdUxQOD.9nV9Ym1xTBiQH1xZ9Xhwi' WHERE username='admin';
mysql> EXIT;
```

#### 10.3.2 清理过期证书

```bash
# 连接到数据库
mysql -u httpsok -p httpsok

# 删除过期证书
mysql> DELETE FROM certificates WHERE valid_to < NOW();
mysql> EXIT;
```

#### 10.3.3 重置应用状态

```bash
# 停止服务
sudo systemctl stop httpsok

# 备份数据
sudo cp -r /var/lib/httpsok /var/lib/httpsok.bak

# 清理缓存
sudo rm -rf /var/lib/httpsok/cache/*

# 启动服务
sudo systemctl start httpsok
```

## 11. 附录

### 11.1 命令参考

```bash
# 服务管理
sudo systemctl start httpsok    # 启动服务
sudo systemctl stop httpsok     # 停止服务
sudo systemctl restart httpsok  # 重启服务
sudo systemctl status httpsok   # 查看服务状态
sudo systemctl enable httpsok   # 设置开机自启
sudo systemctl disable httpsok  # 禁用开机自启

# 日志查看
sudo journalctl -u httpsok                  # 查看服务日志
sudo tail -f /var/log/httpsok/httpsok.log   # 查看应用日志
sudo tail -f /var/log/mysql/error.log       # 查看MySQL错误日志

# 配置管理
sudo nano /etc/httpsok/config.yaml          # 编辑配置文件
sudo systemctl restart httpsok              # 重启服务使配置生效

# 数据库管理
mysql -u httpsok -p httpsok                 # 连接数据库
mysqldump -u httpsok -p httpsok > backup.sql # 备份数据库
mysql -u httpsok -p httpsok < backup.sql    # 恢复数据库
```

### 11.2 配置模板

完整的配置文件模板：

```yaml
# httpsok配置文件

# 应用配置
app:
  name: httpsok
  version: 1.0.0
  port: 8080
  log_dir: /var/log/httpsok
  data_dir: /var/lib/httpsok

# 数据库配置
database:
  driver: mysql
  host: localhost
  port: 3306
  name: httpsok
  user: httpsok
  password: your_password
  max_open_conns: 100
  max_idle_conns: 10
  conn_max_lifetime: 3600

# acme.sh配置
acme:
  path: /usr/local/bin/acme.sh
  default_ca: letsencrypt
  default_encryption: ECC
  renewal_days: 30
  staging: false

# 服务器配置
server:
  use_tls: false
  cert_file: ""
  key_file: ""
  max_workers: 10
  connection_timeout: 30
  read_timeout: 30
  write_timeout: 30
  idle_timeout: 60

# 日志配置
log:
  level: info
  format: json
  output: file
  max_size: 100
  max_age: 30
  max_backups: 10

# 安全配置
security:
  jwt_secret: your_jwt_secret
  jwt_expiry: 86400
  password_salt: your_salt
  enable_csrf: true
  cors_allowed_origins:
    - http://localhost:8080
    - https://example.com
  password_policy:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_number: true
    require_special: true
    max_age: 90
    history_count: 5
  ip_whitelist: []
  rate_limit:
    enabled: true
    requests_per_minute: 60
  encryption:
    key: your_encryption_key
    algorithm: AES-256-GCM

# 缓存配置
cache:
  enabled: true
  type: memory
  ttl: 300
  max_size: 1000

# 监控配置
monitoring:
  prometheus:
    enabled: true
    path: /metrics
  health_check:
    enabled: true
    path: /health
  alert:
    email:
      enabled: false
      smtp_host: smtp.example.com
      smtp_port: 587
      smtp_user: user@example.com
      smtp_password: password
      from: noreply@example.com
    webhook:
      enabled: false
      url: https://webhook.example.com
      method: POST
      headers:
        Content-Type: application/json
        Authorization: Bearer token
```

### 11.3 系统要求检查脚本

创建系统要求检查脚本：

```bash
sudo nano /opt/httpsok/scripts/check_requirements.sh
```

脚本内容：

```bash
#!/bin/bash

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查函数
check() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} $1"
        return 0
    else
        echo -e "${RED}[FAIL]${NC} $1"
        return 1
    fi
}

# 标题
echo -e "${YELLOW}===== httpsok系统要求检查 =====${NC}"

# 检查操作系统
echo -e "\n${YELLOW}检查操作系统:${NC}"
OS=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2 | tr -d '"')
VER=$(cat /etc/os-release | grep "^VERSION_ID=" | cut -d= -f2 | tr -d '"')
echo "操作系统: $OS $VER"

case $OS in
    ubuntu|debian)
        if [[ "$VER" == "18.04" || "$VER" == "20.04" || "$VER" == "22.04" || "$VER" == "10" || "$VER" == "11" ]]; then
            check "操作系统版本兼容"
        else
            check "操作系统版本可能不兼容，推荐使用Ubuntu 18.04/20.04/22.04或Debian 10/11"
        fi
        ;;
    centos|rhel)
        if [[ "$VER" == "7" || "$VER" == "8" ]]; then
            check "操作系统版本兼容"
        else
            check "操作系统版本可能不兼容，推荐使用CentOS/RHEL 7/8"
        fi
        ;;
    *)
        check "未知操作系统，可能不兼容"
        ;;
esac

# 检查硬件资源
echo -e "\n${YELLOW}检查硬件资源:${NC}"

# CPU
CPU_CORES=$(nproc)
echo "CPU核心数: $CPU_CORES"
if [ $CPU_CORES -ge 2 ]; then
    check "CPU核心数满足要求（至少2核）"
else
    check "CPU核心数不满足要求（至少2核）"
fi

# 内存
MEM_TOTAL=$(free -m | grep Mem | awk '{print $2}')
echo "内存大小: $MEM_TOTAL MB"
if [ $MEM_TOTAL -ge 4096 ]; then
    check "内存大小满足要求（至少4GB）"
else
    check "内存大小不满足要求（至少4GB）"
fi

# 磁盘空间
DISK_FREE=$(df -m / | tail -1 | awk '{print $4}')
echo "可用磁盘空间: $DISK_FREE MB"
if [ $DISK_FREE -ge 20480 ]; then
    check "磁盘空间满足要求（至少20GB）"
else
    check "磁盘空间不满足要求（至少20GB）"
fi

# 检查软件依赖
echo -e "\n${YELLOW}检查软件依赖:${NC}"

# Go
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    echo "Go版本: $GO_VERSION"
    if [[ "$GO_VERSION" > "1.16" || "$GO_VERSION" == "1.16" ]]; then
        check "Go版本满足要求（至少1.16）"
    else
        check "Go版本不满足要求（至少1.16）"
    fi
else
    check "未安装Go"
fi

# MySQL
if command -v mysql &> /dev/null; then
    MYSQL_VERSION=$(mysql --version | awk '{print $3}')
    echo "MySQL版本: $MYSQL_VERSION"
    if [[ "$MYSQL_VERSION" > "5.7" || "$MYSQL_VERSION" == "5.7" ]]; then
        check "MySQL版本满足要求（至少5.7）"
    else
        check "MySQL版本不满足要求（至少5.7）"
    fi
else
    check "未安装MySQL"
fi

# 其他依赖
echo -e "\n${YELLOW}检查其他依赖:${NC}"
for cmd in git curl wget; do
    if command -v $cmd &> /dev/null; then
        check "已安装$cmd"
    else
        check "未安装$cmd"
    fi
done

# 检查网络
echo -e "\n${YELLOW}检查网络:${NC}"
if ping -c 1 google.com &> /dev/null; then
    check "可以访问互联网"
else
    check "无法访问互联网"
fi

# 检查端口
echo -e "\n${YELLOW}检查端口:${NC}"
if ! netstat -tulpn 2>/dev/null | grep -q ":8080 "; then
    check "端口8080可用"
else
    check "端口8080已被占用"
fi

# 总结
echo -e "\n${YELLOW}===== 检查完成 =====${NC}"
```

设置执行权限：

```bash
sudo chmod +x /opt/httpsok/scripts/check_requirements.sh
```

运行检查脚本：

```bash
sudo /opt/httpsok/scripts/check_requirements.sh
```
