# Nginx配置文件修改说明

## 概述

本文档说明了为适配httpsok系统复刻版项目而对`ssl.gzyggl.com.conf`文件所做的修改。

## 主要修改内容

### 1. 项目信息更新

- **配置文件头部注释**：更新为"httpsok系统复刻版"
- **后端服务端口**：从8000端口修改为3001端口（根据config.json配置）

### 2. 路径配置调整

#### SSL证书路径
```nginx
# 修改前
ssl_certificate /usr/local/ssl-cert-manager/certificates/ssl.gzyggl.com/fullchain.crt;
ssl_certificate_key /usr/local/ssl-cert-manager/certificates/ssl.gzyggl.com/private.key;
ssl_trusted_certificate /usr/local/ssl-cert-manager/certificates/ssl.gzyggl.com/chain.crt;

# 修改后
ssl_certificate /usr/local/httpsok/certificates/ssl.gzyggl.com/fullchain.crt;
ssl_certificate_key /usr/local/httpsok/certificates/ssl.gzyggl.com/private.key;
ssl_trusted_certificate /usr/local/httpsok/certificates/ssl.gzyggl.com/chain.crt;
```

#### Web根目录路径
```nginx
# 修改前
root /usr/local/ssl-cert-manager/web;

# 修改后
root /usr/local/httpsok/web;
```

### 3. 代理配置优化

#### 后端服务端口更新
所有代理配置从`http://127.0.0.1:8000`更新为`http://127.0.0.1:3001`

#### API路由优化
根据httpsok项目的API结构，添加了更精确的路由配置：

1. **认证端点**（`/api/v1/auth/`）
   - 更严格的频率限制（5r/s）
   - 较小的请求体限制（1M）

2. **核心功能端点**（`/api/v1/(certificates|servers|monitors)/`）
   - 较大的请求体限制（10M，支持证书文件上传）
   - 更长的超时时间（120s，支持证书操作）
   - 适中的频率限制（20r/s）

### 4. 频率限制调整

```nginx
# 修改前
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

# 修改后
limit_req_zone $binary_remote_addr zone=api:10m rate=20r/s;
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/s;
```

- API请求频率从10r/s提升到20r/s
- 新增认证端点专用限制5r/s

### 5. 管理界面配置

- 管理界面路径更新为`/api/v1/admin/`
- 认证提示文本更新为"httpsok System Admin"

### 6. 健康检查端点

健康检查路径更新为`/api/v1/health`，与项目API结构保持一致。

## 配置特点

### 安全性
- 保持了原有的安全头部配置
- 维持了IP访问控制和基本认证
- 继续使用TLS 1.2/1.3和现代加密套件

### 性能优化
- 针对不同类型的API端点设置了不同的超时和限制
- 静态文件缓存配置保持不变
- 连接限制和频率限制根据实际需求调整

### 兼容性
- 支持HTTP/2
- 保持了WebSocket升级支持
- 错误页面配置完整

## 部署建议

1. **证书路径**：确保SSL证书文件存放在`/usr/local/httpsok/certificates/`目录下
2. **Web文件**：前端文件应部署到`/usr/local/httpsok/web/`目录
3. **日志目录**：确保Nginx有权限写入`/var/log/nginx/`目录
4. **认证文件**：管理员访问需要配置`/etc/nginx/.htpasswd`文件

## 测试建议

部署后建议测试以下功能：
- [ ] HTTPS访问正常
- [ ] API端点响应正常（/api/v1/health）
- [ ] 认证功能正常（/api/v1/auth/login）
- [ ] 管理界面访问控制正常
- [ ] 静态文件加载正常
- [ ] 错误页面显示正常

## 注意事项

1. 确保httpsok后端服务运行在3001端口
2. 检查防火墙设置，确保3001端口可访问
3. 验证SSL证书路径和权限设置
4. 测试各项安全头部是否正确设置
