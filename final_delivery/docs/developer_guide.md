# httpsok系统开发文档

## 1. 系统架构

### 1.1 整体架构

httpsok系统采用前后端分离的架构，主要由以下几个部分组成：

- **前端**：基于HTML/CSS/JavaScript开发的Web界面
- **后端API**：基于Go语言开发的RESTful API服务
- **数据库**：MySQL数据库，存储系统数据
- **客户端脚本**：部署在目标服务器上的脚本，用于收集信息和部署证书
- **acme.sh集成**：与acme.sh交互，实现证书申请和续期

系统架构图如下：

```
+----------------+      +----------------+      +----------------+
|                |      |                |      |                |
|  Web前端界面   +----->+  后端API服务   +----->+  MySQL数据库   |
|                |      |                |      |                |
+----------------+      +------+---------+      +----------------+
                               |
                               v
                        +------+---------+
                        |                |
                        |  acme.sh集成   |
                        |                |
                        +------+---------+
                               |
                               v
                        +------+---------+
                        |                |
                        |  客户端脚本    |
                        |                |
                        +----------------+
```

### 1.2 技术栈

- **前端**：HTML5, CSS3, JavaScript, Bootstrap, jQuery
- **后端**：Go 1.16+, Gin Web框架
- **数据库**：MySQL 5.7+
- **客户端**：Bash脚本
- **部署**：Docker, Systemd
- **证书工具**：acme.sh

### 1.3 目录结构

```
httpsok/
├── cmd/                    # 命令行入口
│   └── main.go             # 主程序入口
├── configs/                # 配置文件
│   └── config.yaml         # 主配置文件
├── docs/                   # 文档
│   ├── api_reference.md    # API参考文档
│   ├── deployment_guide.md # 部署指南
│   ├── developer_guide.md  # 开发文档
│   └── user_manual.md      # 用户手册
├── internal/               # 内部包
│   ├── config/             # 配置处理
│   ├── controllers/        # 控制器
│   ├── database/           # 数据库连接
│   ├── logger/             # 日志处理
│   ├── middleware/         # 中间件
│   ├── models/             # 数据模型
│   ├── server/             # 服务器
│   └── services/           # 业务服务
├── pkg/                    # 公共包
│   ├── acme/               # acme.sh封装
│   ├── utils/              # 工具函数
│   └── validator/          # 数据验证
├── scripts/                # 脚本
│   ├── deploy.sh           # 部署脚本
│   └── schema.sql          # 数据库结构
├── tests/                  # 测试
│   ├── api_test.go         # API测试
│   └── e2e_test.sh         # 端到端测试
└── web/                    # Web前端
    ├── assets/             # 静态资源
    │   ├── css/            # 样式表
    │   ├── js/             # JavaScript
    │   └── img/            # 图片
    ├── public/             # 公共文件
    └── src/                # 源代码
        ├── index.html      # 首页
        ├── certificates.html # 证书管理页面
        ├── servers.html    # 服务器管理页面
        └── monitors.html   # 证书监控页面
```

## 2. 数据库设计

### 2.1 ER图

系统的核心实体关系如下：

```
+-------------+       +-------------+       +-------------+
|             |       |             |       |             |
|    User     +-------+  Certificate+-------+   Server    |
|             |       |             |       |             |
+-------------+       +------+------+       +-------------+
                             |
                             |
                      +------v------+
                      |             |
                      |   Monitor   |
                      |             |
                      +-------------+
```

### 2.2 表结构

#### 2.2.1 users表

存储系统用户信息。

| 字段名      | 类型         | 描述                 | 约束           |
|------------|--------------|---------------------|----------------|
| id         | INT          | 用户ID               | PK, AUTO_INCREMENT |
| username   | VARCHAR(50)  | 用户名               | UNIQUE, NOT NULL |
| password   | VARCHAR(255) | 密码哈希             | NOT NULL       |
| email      | VARCHAR(100) | 电子邮箱             | UNIQUE         |
| role       | VARCHAR(20)  | 角色（admin/user）   | NOT NULL       |
| created_at | TIMESTAMP    | 创建时间             | NOT NULL       |
| updated_at | TIMESTAMP    | 更新时间             | NOT NULL       |

#### 2.2.2 certificates表

存储证书信息。

| 字段名          | 类型         | 描述                 | 约束           |
|----------------|--------------|---------------------|----------------|
| id             | INT          | 证书ID               | PK, AUTO_INCREMENT |
| user_id        | INT          | 所属用户ID           | FK, NOT NULL   |
| domain         | VARCHAR(255) | 域名                 | NOT NULL       |
| ca_type        | VARCHAR(50)  | CA类型               | NOT NULL       |
| encryption_type| VARCHAR(10)  | 加密类型（ECC/RSA）  | NOT NULL       |
| status         | VARCHAR(20)  | 状态                 | NOT NULL       |
| cert_file      | TEXT         | 证书文件内容         |                |
| key_file       | TEXT         | 私钥文件内容         |                |
| chain_file     | TEXT         | 证书链文件内容       |                |
| valid_from     | TIMESTAMP    | 有效期开始           |                |
| valid_to       | TIMESTAMP    | 有效期结束           |                |
| dns_validated  | BOOLEAN      | 是否通过DNS验证      | NOT NULL       |
| notes          | TEXT         | 备注                 |                |
| created_at     | TIMESTAMP    | 创建时间             | NOT NULL       |
| updated_at     | TIMESTAMP    | 更新时间             | NOT NULL       |

#### 2.2.3 servers表

存储服务器信息。

| 字段名          | 类型         | 描述                 | 约束           |
|----------------|--------------|---------------------|----------------|
| id             | INT          | 服务器ID             | PK, AUTO_INCREMENT |
| user_id        | INT          | 所属用户ID           | FK, NOT NULL   |
| name           | VARCHAR(100) | 服务器名称           | NOT NULL       |
| type           | VARCHAR(20)  | 服务器类型           | NOT NULL       |
| hostname       | VARCHAR(255) | 主机名/IP            | NOT NULL       |
| os_type        | VARCHAR(50)  | 操作系统类型         | NOT NULL       |
| os_version     | VARCHAR(50)  | 操作系统版本         |                |
| version        | VARCHAR(50)  | Web服务器版本        |                |
| port           | INT          | SSH端口              | NOT NULL       |
| username       | VARCHAR(50)  | SSH用户名            | NOT NULL       |
| auth_type      | VARCHAR(20)  | 认证类型             | NOT NULL       |
| auth_data      | TEXT         | 认证数据（加密）     |                |
| status         | VARCHAR(20)  | 状态                 | NOT NULL       |
| auto_deploy    | BOOLEAN      | 是否自动部署         | NOT NULL       |
| last_check     | TIMESTAMP    | 最后检查时间         |                |
| notes          | TEXT         | 备注                 |                |
| created_at     | TIMESTAMP    | 创建时间             | NOT NULL       |
| updated_at     | TIMESTAMP    | 更新时间             | NOT NULL       |

#### 2.2.4 monitors表

存储证书监控信息。

| 字段名          | 类型         | 描述                 | 约束           |
|----------------|--------------|---------------------|----------------|
| id             | INT          | 监控ID               | PK, AUTO_INCREMENT |
| user_id        | INT          | 所属用户ID           | FK, NOT NULL   |
| certificate_id | INT          | 关联证书ID           | FK             |
| host           | VARCHAR(255) | 主机域名             | NOT NULL       |
| port           | INT          | 端口                 | NOT NULL       |
| ip_type        | VARCHAR(20)  | IP类型               | NOT NULL       |
| ip             | VARCHAR(45)  | IP地址               |                |
| status         | VARCHAR(20)  | 状态                 | NOT NULL       |
| grade          | VARCHAR(10)  | 证书等级             |                |
| encryption_type| VARCHAR(10)  | 加密类型             |                |
| valid_days     | INT          | 有效天数             |                |
| check_interval | INT          | 检查间隔（分钟）     | NOT NULL       |
| enabled        | BOOLEAN      | 是否启用             | NOT NULL       |
| last_check     | TIMESTAMP    | 最后检查时间         |                |
| notes          | TEXT         | 备注                 |                |
| created_at     | TIMESTAMP    | 创建时间             | NOT NULL       |
| updated_at     | TIMESTAMP    | 更新时间             | NOT NULL       |

#### 2.2.5 deployments表

存储证书部署记录。

| 字段名          | 类型         | 描述                 | 约束           |
|----------------|--------------|---------------------|----------------|
| id             | INT          | 部署ID               | PK, AUTO_INCREMENT |
| certificate_id | INT          | 证书ID               | FK, NOT NULL   |
| server_id      | INT          | 服务器ID             | FK, NOT NULL   |
| cert_path      | VARCHAR(255) | 证书路径             | NOT NULL       |
| key_path       | VARCHAR(255) | 私钥路径             | NOT NULL       |
| chain_path     | VARCHAR(255) | 证书链路径           |                |
| config_path    | VARCHAR(255) | 配置文件路径         |                |
| status         | VARCHAR(20)  | 状态                 | NOT NULL       |
| deployed_at    | TIMESTAMP    | 部署时间             |                |
| created_at     | TIMESTAMP    | 创建时间             | NOT NULL       |
| updated_at     | TIMESTAMP    | 更新时间             | NOT NULL       |

#### 2.2.6 logs表

存储系统日志。

| 字段名      | 类型         | 描述                 | 约束           |
|------------|--------------|---------------------|----------------|
| id         | INT          | 日志ID               | PK, AUTO_INCREMENT |
| user_id    | INT          | 用户ID               | FK             |
| level      | VARCHAR(10)  | 日志级别             | NOT NULL       |
| category   | VARCHAR(50)  | 日志类别             | NOT NULL       |
| message    | TEXT         | 日志消息             | NOT NULL       |
| data       | TEXT         | 附加数据（JSON）     |                |
| created_at | TIMESTAMP    | 创建时间             | NOT NULL       |

### 2.3 索引设计

为提高查询性能，系统设计了以下索引：

- `users` 表：
  - `username_idx`：用户名索引
  - `email_idx`：邮箱索引
  
- `certificates` 表：
  - `user_id_idx`：用户ID索引
  - `domain_idx`：域名索引
  - `status_idx`：状态索引
  - `valid_to_idx`：有效期结束索引
  
- `servers` 表：
  - `user_id_idx`：用户ID索引
  - `hostname_idx`：主机名索引
  - `status_idx`：状态索引
  
- `monitors` 表：
  - `user_id_idx`：用户ID索引
  - `certificate_id_idx`：证书ID索引
  - `host_idx`：主机域名索引
  - `status_idx`：状态索引
  
- `deployments` 表：
  - `certificate_id_idx`：证书ID索引
  - `server_id_idx`：服务器ID索引
  - `status_idx`：状态索引
  
- `logs` 表：
  - `user_id_idx`：用户ID索引
  - `level_idx`：日志级别索引
  - `category_idx`：日志类别索引
  - `created_at_idx`：创建时间索引

## 3. 后端API设计

### 3.1 API概述

httpsok系统的后端API采用RESTful风格设计，主要包括以下几个部分：

- 认证API：用户登录、注销、刷新令牌等
- 证书API：证书的CRUD操作、申请、验证、下载等
- 服务器API：服务器的CRUD操作、连接测试、状态检查等
- 监控API：监控的CRUD操作、状态检查等
- 系统API：系统状态、配置、日志等

### 3.2 认证机制

系统采用JWT（JSON Web Token）进行认证，流程如下：

1. 用户提交用户名和密码
2. 服务器验证用户名和密码
3. 验证通过后，生成JWT令牌
4. 客户端在后续请求中携带JWT令牌
5. 服务器验证JWT令牌的有效性
6. 令牌有效则处理请求，否则返回401错误

### 3.3 API端点

#### 3.3.1 认证API

- `POST /api/v1/auth/login`：用户登录
  - 请求：`{"username": "admin", "password": "password"}`
  - 响应：`{"success": true, "data": {"token": "xxx", "expires_at": "xxx"}}`

- `POST /api/v1/auth/logout`：用户注销
  - 请求：无
  - 响应：`{"success": true}`

- `POST /api/v1/auth/refresh`：刷新令牌
  - 请求：无（使用当前令牌）
  - 响应：`{"success": true, "data": {"token": "xxx", "expires_at": "xxx"}}`

#### 3.3.2 证书API

- `GET /api/v1/certificates`：获取证书列表
  - 请求参数：`page`, `limit`, `search`, `status`, `sort`
  - 响应：`{"success": true, "data": {"certificates": [...], "total": 100}}`

- `GET /api/v1/certificates/{id}`：获取证书详情
  - 响应：`{"success": true, "data": {"certificate": {...}}}`

- `POST /api/v1/certificates`：创建证书
  - 请求：`{"domain": "example.com", "ca_type": "letsencrypt", ...}`
  - 响应：`{"success": true, "data": {"certificate": {...}}}`

- `PATCH /api/v1/certificates/{id}`：更新证书
  - 请求：`{"notes": "Updated notes"}`
  - 响应：`{"success": true, "data": {"certificate": {...}}}`

- `DELETE /api/v1/certificates/{id}`：删除证书
  - 响应：`{"success": true}`

- `POST /api/v1/certificates/{id}/validate`：验证域名
  - 响应：`{"success": true, "data": {"validation": {...}}}`

- `POST /api/v1/certificates/{id}/issue`：申请证书
  - 响应：`{"success": true, "data": {"certificate": {...}}}`

- `GET /api/v1/certificates/{id}/download`：下载证书
  - 请求参数：`type` (cert/key/chain/fullchain)
  - 响应：证书文件内容

#### 3.3.3 服务器API

- `GET /api/v1/servers`：获取服务器列表
  - 请求参数：`page`, `limit`, `search`, `status`, `sort`
  - 响应：`{"success": true, "data": {"servers": [...], "total": 100}}`

- `GET /api/v1/servers/{id}`：获取服务器详情
  - 响应：`{"success": true, "data": {"server": {...}}}`

- `POST /api/v1/servers`：创建服务器
  - 请求：`{"name": "Web Server", "type": "nginx", ...}`
  - 响应：`{"success": true, "data": {"server": {...}}}`

- `PATCH /api/v1/servers/{id}`：更新服务器
  - 请求：`{"name": "Updated Name", "auto_deploy": true}`
  - 响应：`{"success": true, "data": {"server": {...}}}`

- `DELETE /api/v1/servers/{id}`：删除服务器
  - 响应：`{"success": true}`

- `POST /api/v1/servers/{id}/test`：测试服务器连接
  - 响应：`{"success": true, "data": {"status": "connected"}}`

- `POST /api/v1/servers/{id}/deploy`：部署证书
  - 请求：`{"certificate_id": 123, "cert_path": "/etc/nginx/certs/cert.pem", ...}`
  - 响应：`{"success": true, "data": {"deployment": {...}}}`

#### 3.3.4 监控API

- `GET /api/v1/monitors`：获取监控列表
  - 请求参数：`page`, `limit`, `search`, `status`, `sort`
  - 响应：`{"success": true, "data": {"monitors": [...], "total": 100}}`

- `GET /api/v1/monitors/{id}`：获取监控详情
  - 响应：`{"success": true, "data": {"monitor": {...}}}`

- `POST /api/v1/monitors`：创建监控
  - 请求：`{"host": "example.com", "port": 443, ...}`
  - 响应：`{"success": true, "data": {"monitor": {...}}}`

- `PATCH /api/v1/monitors/{id}`：更新监控
  - 请求：`{"enabled": true, "check_interval": 60}`
  - 响应：`{"success": true, "data": {"monitor": {...}}}`

- `DELETE /api/v1/monitors/{id}`：删除监控
  - 响应：`{"success": true}`

- `POST /api/v1/monitors/{id}/check`：检查证书状态
  - 响应：`{"success": true, "data": {"status": "valid", "valid_days": 30, ...}}`

#### 3.3.5 系统API

- `GET /api/v1/health`：健康检查
  - 响应：`{"status": "ok", "version": "1.0.0"}`

- `GET /api/v1/settings`：获取系统设置
  - 响应：`{"success": true, "data": {"settings": {...}}}`

- `PATCH /api/v1/settings`：更新系统设置
  - 请求：`{"default_ca": "letsencrypt", "renewal_days": 30}`
  - 响应：`{"success": true, "data": {"settings": {...}}}`

- `GET /api/v1/logs`：获取系统日志
  - 请求参数：`page`, `limit`, `level`, `category`, `start_date`, `end_date`
  - 响应：`{"success": true, "data": {"logs": [...], "total": 100}}`

### 3.4 错误处理

API的错误响应格式如下：

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Error message",
    "details": {}
  }
}
```

常见错误码：

- `UNAUTHORIZED`：未授权（401）
- `FORBIDDEN`：禁止访问（403）
- `NOT_FOUND`：资源不存在（404）
- `VALIDATION_ERROR`：验证错误（422）
- `INTERNAL_ERROR`：内部错误（500）

## 4. 前端设计

### 4.1 页面结构

httpsok系统的前端主要包括以下页面：

- 登录页面：用户登录
- 仪表盘：系统概览
- 证书管理：证书的CRUD操作
- 自动部署：服务器管理和证书部署
- 证书监控：证书状态监控
- 系统设置：用户管理、系统配置、日志查看

### 4.2 技术选型

前端采用以下技术：

- HTML5：页面结构
- CSS3：样式表
- JavaScript：交互逻辑
- Bootstrap：UI框架
- jQuery：DOM操作和AJAX请求
- Chart.js：数据可视化

### 4.3 响应式设计

系统采用响应式设计，适配不同屏幕尺寸：

- 桌面端：宽屏布局，多列显示
- 平板端：中等宽度布局，部分内容折叠
- 移动端：窄屏布局，单列显示，导航折叠

### 4.4 主题定制

系统支持主题定制，包括：

- 明亮主题：白色背景，深色文字
- 暗黑主题：深色背景，浅色文字
- 品牌色定制：可根据需要调整主题色

## 5. 核心功能实现

### 5.1 证书申请流程

证书申请流程如下：

1. 用户填写域名、CA类型、加密类型等信息
2. 系统生成DNS验证记录
3. 用户添加DNS记录
4. 系统验证DNS记录
5. 验证通过后，调用acme.sh申请证书
6. 证书申请成功后，保存证书信息到数据库

代码示例：

```go
// 申请证书
func (s *CertificateService) IssueCertificate(cert *models.Certificate) error {
    // 1. 验证域名
    if !cert.DNSValidated {
        return errors.New("domain not validated")
    }
    
    // 2. 调用acme.sh申请证书
    acmeClient := acme.NewClient()
    result, err := acmeClient.Issue(cert.Domain, cert.CAType, cert.EncryptionType)
    if err != nil {
        return err
    }
    
    // 3. 更新证书信息
    cert.CertFile = result.CertFile
    cert.KeyFile = result.KeyFile
    cert.ChainFile = result.ChainFile
    cert.ValidFrom = result.ValidFrom
    cert.ValidTo = result.ValidTo
    cert.Status = "issued"
    
    // 4. 保存到数据库
    return s.repo.Update(cert)
}
```

### 5.2 证书部署流程

证书部署流程如下：

1. 用户选择证书和目标服务器
2. 用户填写证书路径信息
3. 系统连接服务器
4. 系统将证书文件上传到服务器
5. 系统更新Web服务器配置
6. 系统重载Web服务器

代码示例：

```go
// 部署证书
func (s *ServerService) DeployCertificate(deployment *models.Deployment) error {
    // 1. 获取证书和服务器信息
    cert, err := s.certRepo.GetByID(deployment.CertificateID)
    if err != nil {
        return err
    }
    
    server, err := s.repo.GetByID(deployment.ServerID)
    if err != nil {
        return err
    }
    
    // 2. 连接服务器
    sshClient, err := ssh.Connect(server.Hostname, server.Port, server.Username, server.GetAuthMethod())
    if err != nil {
        return err
    }
    defer sshClient.Close()
    
    // 3. 上传证书文件
    if err := sshClient.UploadFile([]byte(cert.CertFile), deployment.CertPath); err != nil {
        return err
    }
    
    if err := sshClient.UploadFile([]byte(cert.KeyFile), deployment.KeyPath); err != nil {
        return err
    }
    
    if cert.ChainFile != "" && deployment.ChainPath != "" {
        if err := sshClient.UploadFile([]byte(cert.ChainFile), deployment.ChainPath); err != nil {
            return err
        }
    }
    
    // 4. 重载Web服务器
    var reloadCmd string
    switch server.Type {
    case "nginx":
        reloadCmd = "nginx -s reload"
    case "apache":
        reloadCmd = "apachectl -k graceful"
    default:
        return errors.New("unsupported server type")
    }
    
    if _, err := sshClient.RunCommand(reloadCmd); err != nil {
        return err
    }
    
    // 5. 更新部署状态
    deployment.Status = "deployed"
    deployment.DeployedAt = time.Now()
    
    return s.deployRepo.Update(deployment)
}
```

### 5.3 证书监控流程

证书监控流程如下：

1. 系统定期检查证书状态
2. 系统连接目标主机，获取证书信息
3. 系统解析证书，提取有效期等信息
4. 系统更新监控状态
5. 如果证书即将过期，系统发送告警

代码示例：

```go
// 检查证书状态
func (s *MonitorService) CheckCertificate(monitor *models.Monitor) (*models.CheckResult, error) {
    // 1. 连接目标主机，获取证书
    cert, err := ssl.GetCertificate(monitor.Host, monitor.Port)
    if err != nil {
        return nil, err
    }
    
    // 2. 解析证书信息
    result := &models.CheckResult{
        MonitorID:      monitor.ID,
        Status:         "valid",
        Grade:          ssl.GetGrade(cert),
        EncryptionType: ssl.GetEncryptionType(cert),
        ValidFrom:      cert.NotBefore,
        ValidTo:        cert.NotAfter,
        ValidDays:      int(cert.NotAfter.Sub(time.Now()).Hours() / 24),
        CheckedAt:      time.Now(),
    }
    
    // 3. 判断证书状态
    if result.ValidDays <= 0 {
        result.Status = "expired"
    } else if result.ValidDays <= 7 {
        result.Status = "critical"
    } else if result.ValidDays <= 30 {
        result.Status = "warning"
    }
    
    // 4. 更新监控状态
    monitor.Status = result.Status
    monitor.Grade = result.Grade
    monitor.EncryptionType = result.EncryptionType
    monitor.ValidDays = result.ValidDays
    monitor.LastCheck = result.CheckedAt
    
    if err := s.repo.Update(monitor); err != nil {
        return nil, err
    }
    
    // 5. 保存检查结果
    if err := s.resultRepo.Create(result); err != nil {
        return nil, err
    }
    
    // 6. 发送告警（如果需要）
    if result.Status == "critical" || result.Status == "warning" {
        s.alertService.SendAlert(monitor, result)
    }
    
    return result, nil
}
```

### 5.4 自动续期流程

自动续期流程如下：

1. 系统定期检查证书有效期
2. 对于即将过期的证书，系统自动触发续期
3. 系统调用acme.sh续期证书
4. 续期成功后，系统更新证书信息
5. 如果启用了自动部署，系统自动部署新证书

代码示例：

```go
// 自动续期证书
func (s *CertificateService) AutoRenew() error {
    // 1. 获取即将过期的证书
    certs, err := s.repo.GetExpiringCertificates(30) // 30天内过期
    if err != nil {
        return err
    }
    
    for _, cert := range certs {
        // 2. 调用acme.sh续期证书
        acmeClient := acme.NewClient()
        result, err := acmeClient.Renew(cert.Domain, cert.CAType, cert.EncryptionType)
        if err != nil {
            s.logger.Error("Failed to renew certificate", "domain", cert.Domain, "error", err)
            continue
        }
        
        // 3. 更新证书信息
        cert.CertFile = result.CertFile
        cert.KeyFile = result.KeyFile
        cert.ChainFile = result.ChainFile
        cert.ValidFrom = result.ValidFrom
        cert.ValidTo = result.ValidTo
        
        if err := s.repo.Update(cert); err != nil {
            s.logger.Error("Failed to update certificate", "domain", cert.Domain, "error", err)
            continue
        }
        
        // 4. 自动部署（如果需要）
        deployments, err := s.deployRepo.GetByCertificateID(cert.ID)
        if err != nil {
            s.logger.Error("Failed to get deployments", "cert_id", cert.ID, "error", err)
            continue
        }
        
        for _, deployment := range deployments {
            server, err := s.serverRepo.GetByID(deployment.ServerID)
            if err != nil {
                s.logger.Error("Failed to get server", "server_id", deployment.ServerID, "error", err)
                continue
            }
            
            if server.AutoDeploy {
                if err := s.serverService.DeployCertificate(deployment); err != nil {
                    s.logger.Error("Failed to deploy certificate", "deployment_id", deployment.ID, "error", err)
                    continue
                }
                
                s.logger.Info("Certificate auto-deployed", "domain", cert.Domain, "server", server.Name)
            }
        }
        
        s.logger.Info("Certificate renewed", "domain", cert.Domain, "valid_to", cert.ValidTo)
    }
    
    return nil
}
```

## 6. 安全设计

### 6.1 认证与授权

系统采用以下安全措施：

- 密码哈希：使用bcrypt算法哈希存储密码
- JWT认证：使用JWT进行API认证
- RBAC权限：基于角色的访问控制
- CSRF防护：防止跨站请求伪造
- 会话超时：自动注销长时间不活动的会话

### 6.2 数据安全

数据安全措施包括：

- 敏感数据加密：加密存储私钥和认证信息
- HTTPS传输：所有API通信使用HTTPS
- 输入验证：严格验证所有用户输入
- SQL注入防护：使用参数化查询
- XSS防护：过滤用户输入的HTML内容

### 6.3 日志与审计

系统实现了完善的日志和审计功能：

- 操作日志：记录所有关键操作
- 安全日志：记录登录、注销、权限变更等安全事件
- 系统日志：记录系统启动、关闭、错误等事件
- 审计跟踪：支持按用户、时间、操作类型等条件查询日志

## 7. 测试策略

### 7.1 单元测试

单元测试覆盖以下方面：

- 模型测试：验证数据模型的CRUD操作
- 服务测试：验证业务逻辑的正确性
- 控制器测试：验证API接口的行为
- 工具函数测试：验证辅助函数的正确性

### 7.2 集成测试

集成测试覆盖以下方面：

- API测试：验证API端点的功能
- 数据库测试：验证数据库操作的正确性
- 外部服务集成测试：验证与acme.sh等外部服务的集成

### 7.3 端到端测试

端到端测试覆盖以下方面：

- 用户流程测试：验证完整的用户操作流程
- 证书申请测试：验证证书申请流程
- 证书部署测试：验证证书部署流程
- 证书监控测试：验证证书监控流程

### 7.4 性能测试

性能测试覆盖以下方面：

- 负载测试：验证系统在高负载下的性能
- 并发测试：验证系统在多用户并发访问下的性能
- 长时间运行测试：验证系统在长时间运行下的稳定性

## 8. 部署与运维

### 8.1 部署方式

系统支持以下部署方式：

- 标准部署：直接部署到物理机或虚拟机
- Docker部署：使用Docker容器部署
- Kubernetes部署：使用Kubernetes编排部署

### 8.2 监控与告警

系统实现了以下监控和告警功能：

- 系统监控：监控CPU、内存、磁盘等系统资源
- 应用监控：监控API响应时间、错误率等应用指标
- 证书监控：监控证书状态和有效期
- 告警通知：支持邮件、短信、Webhook等告警方式

### 8.3 备份与恢复

系统实现了以下备份和恢复功能：

- 数据库备份：定期备份数据库
- 证书备份：备份所有证书和私钥
- 配置备份：备份系统配置
- 恢复流程：提供数据恢复的详细流程

### 8.4 扩展性设计

系统的扩展性设计包括：

- 水平扩展：支持多实例部署
- 负载均衡：支持API服务的负载均衡
- 数据库扩展：支持数据库主从复制和分片
- 模块化设计：支持功能模块的独立扩展

## 9. 开发规范

### 9.1 代码规范

Go代码规范：

- 遵循Go官方代码规范
- 使用gofmt格式化代码
- 使用golint和golangci-lint进行代码检查
- 遵循包的命名和组织规范

前端代码规范：

- 遵循HTML5、CSS3标准
- 使用ESLint检查JavaScript代码
- 使用Prettier格式化代码
- 遵循BEM命名规范

### 9.2 Git工作流

开发团队采用以下Git工作流：

- 主分支：master（生产环境）
- 开发分支：develop（开发环境）
- 功能分支：feature/*（新功能开发）
- 修复分支：bugfix/*（bug修复）
- 发布分支：release/*（版本发布准备）
- 热修复分支：hotfix/*（生产环境紧急修复）

### 9.3 版本控制

系统采用语义化版本控制（Semantic Versioning）：

- 主版本号：不兼容的API变更
- 次版本号：向后兼容的功能性新增
- 修订号：向后兼容的问题修正

### 9.4 文档规范

系统文档包括：

- API文档：使用Swagger/OpenAPI规范
- 代码注释：遵循godoc规范
- 用户手册：面向最终用户的使用指南
- 开发文档：面向开发人员的技术文档
- 部署指南：面向运维人员的部署文档

## 10. 项目管理

### 10.1 开发流程

项目采用敏捷开发流程：

- 需求分析：收集和分析用户需求
- 设计：系统架构和详细设计
- 开发：编码和单元测试
- 测试：集成测试和端到端测试
- 部署：部署到生产环境
- 维护：bug修复和功能增强

### 10.2 任务管理

项目使用以下工具进行任务管理：

- Jira：任务跟踪和项目管理
- Confluence：文档协作
- Slack：团队沟通
- GitLab：代码仓库和CI/CD

### 10.3 质量保证

项目实施以下质量保证措施：

- 代码审查：所有代码变更需要经过审查
- 自动化测试：单元测试、集成测试和端到端测试
- 持续集成：自动构建和测试
- 持续部署：自动部署到测试环境

### 10.4 风险管理

项目实施以下风险管理措施：

- 风险识别：定期识别潜在风险
- 风险评估：评估风险的影响和可能性
- 风险缓解：制定风险缓解计划
- 风险监控：持续监控风险状态
