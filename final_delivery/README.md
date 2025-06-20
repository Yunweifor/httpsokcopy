# httpsok系统复刻版 - 项目交付清单

## 1. 项目概述

httpsok系统复刻版是一个基于Go语言和MySQL的SSL证书自动化管理系统，旨在提供便捷、高效的SSL证书申请、部署和监控服务。系统集成了acme.sh，实现了证书的自动申请、验证、部署和续期，大大简化了SSL证书的管理流程。

## 2. 交付内容

### 2.1 源代码

- **后端代码**
  - `/cmd`：应用入口和主程序
  - `/internal`：内部包，包含核心业务逻辑
    - `/models`：数据模型
    - `/controllers`：API控制器
    - `/services`：业务服务
    - `/middleware`：中间件
    - `/database`：数据库连接和操作
  - `/pkg`：可重用的公共包

- **前端代码**
  - `/web/src`：前端源代码
  - `/web/assets`：静态资源（CSS、JavaScript、图片等）
  - `/web/public`：公共资源

### 2.2 数据库

- `/scripts/schema.sql`：数据库结构定义脚本

### 2.3 配置文件

- `/configs`：配置文件目录

### 2.4 脚本

- `/scripts/deploy.sh`：部署脚本
- `/scripts/backup.sh`：备份脚本
- `/scripts/check_requirements.sh`：系统要求检查脚本

### 2.5 测试

- `/tests/api_test.go`：API测试
- `/tests/e2e_test.sh`：端到端测试脚本

### 2.6 文档

- `/docs/user_manual.md`：用户手册
- `/docs/developer_guide.md`：开发文档
- `/docs/deployment_guide.md`：部署指南
- `/docs/api_reference.md`：API参考文档

## 3. 系统功能

### 3.1 证书管理

- 免费SSL证书申请（支持Let's Encrypt、ZeroSSL、Google Trust Services）
- 支持ECC和RSA加密算法
- 支持通配符证书和多域名证书
- DNS验证域名所有权
- 证书状态监控和自动续期
- 证书下载（多种格式）

### 3.2 服务器管理

- 自动扫描和发现Web服务器
- 支持Nginx和Apache
- 自动部署证书到服务器
- 自动重载Web服务器配置

### 3.3 证书监控

- 实时监控证书状态
- 证书过期预警
- 监控历史记录
- 自定义监控参数

### 3.4 用户管理

- 多用户支持
- 基于角色的权限控制
- 安全认证

## 4. 技术栈

### 4.1 后端

- **语言**：Go 1.16+
- **框架**：Gin
- **数据库**：MySQL 5.7+
- **ORM**：GORM
- **认证**：JWT
- **日志**：zap
- **配置**：viper
- **证书工具**：acme.sh

### 4.2 前端

- **框架**：Vue.js
- **UI组件**：Element UI
- **HTTP客户端**：Axios
- **状态管理**：Vuex
- **路由**：Vue Router

## 5. 部署要求

### 5.1 硬件要求

- **CPU**：2核心或更高
- **内存**：4GB或更高
- **磁盘空间**：20GB或更高
- **网络**：可访问互联网

### 5.2 软件要求

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

## 6. 安装指南

详细的安装步骤请参考`/docs/deployment_guide.md`文件。

## 7. 使用指南

详细的使用说明请参考`/docs/user_manual.md`文件。

## 8. API文档

API接口详细说明请参考`/docs/api_reference.md`文件。

## 9. 开发指南

如需进行二次开发，请参考`/docs/developer_guide.md`文件。

## 10. 联系方式

如有任何问题或需要技术支持，请联系：

- **邮箱**：support@example.com
- **网站**：https://www.example.com
- **GitHub**：https://github.com/example/httpsok
