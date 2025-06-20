# httpsok系统 API文档

## 概述

本文档详细描述了httpsok系统的API接口规范，包括认证机制、请求格式、响应格式和错误处理等内容。所有API均采用RESTful风格设计，使用JSON作为数据交换格式。

## 基础信息

- **基础URL**: `https://your-domain.com/api/v1`
- **内容类型**: `application/json`
- **字符编码**: `UTF-8`

## 认证机制

httpsok系统使用JWT（JSON Web Token）进行API认证。除了登录和注册接口外，所有API请求都需要在HTTP头部包含有效的认证令牌。

### 获取令牌

通过登录接口获取JWT令牌：

```
POST /auth/login
```

请求示例：

```json
{
  "username": "admin",
  "password": "your_password"
}
```

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_at": "2025-07-20T06:24:49Z",
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin",
      "created_at": "2025-06-20T06:24:49Z"
    }
  }
}
```

### 使用令牌

在所有需要认证的API请求中，将JWT令牌添加到HTTP头部：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 通用响应格式

所有API响应均使用统一的JSON格式：

```json
{
  "code": 0,          // 状态码，0表示成功，非0表示错误
  "message": "success", // 状态描述
  "data": {}          // 响应数据，可能是对象、数组或null
}
```

## 错误处理

当API请求失败时，响应中的`code`字段将包含非零值，`message`字段将包含错误描述。

错误响应示例：

```json
{
  "code": 1001,
  "message": "Invalid credentials",
  "data": null
}
```

### 常见错误码

| 错误码 | 描述 |
|--------|------|
| 1000 | 服务器内部错误 |
| 1001 | 认证失败 |
| 1002 | 权限不足 |
| 1003 | 请求参数错误 |
| 1004 | 资源不存在 |
| 1005 | 资源已存在 |
| 1006 | 操作失败 |

## API接口

### 1. 用户管理

#### 1.1 用户注册

```
POST /users/register
```

请求参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| username | string | 是 | 用户名，长度3-20个字符 |
| password | string | 是 | 密码，长度8-30个字符 |
| email | string | 是 | 电子邮箱 |

请求示例：

```json
{
  "username": "newuser",
  "password": "Password123!",
  "email": "user@example.com"
}
```

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 2,
    "username": "newuser",
    "email": "user@example.com",
    "created_at": "2025-06-20T06:24:49Z"
  }
}
```

#### 1.2 用户登录

```
POST /auth/login
```

请求参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| username | string | 是 | 用户名 |
| password | string | 是 | 密码 |

请求示例：

```json
{
  "username": "admin",
  "password": "your_password"
}
```

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_at": "2025-07-20T06:24:49Z",
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin",
      "created_at": "2025-06-20T06:24:49Z"
    }
  }
}
```

#### 1.3 获取用户信息

```
GET /users/me
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "created_at": "2025-06-20T06:24:49Z",
    "last_login": "2025-06-20T06:24:49Z"
  }
}
```

#### 1.4 修改用户密码

```
PUT /users/password
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

请求参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| old_password | string | 是 | 旧密码 |
| new_password | string | 是 | 新密码，长度8-30个字符 |

请求示例：

```json
{
  "old_password": "your_old_password",
  "new_password": "your_new_password"
}
```

响应示例：

```json
{
  "code": 0,
  "message": "Password updated successfully",
  "data": null
}
```

### 2. 证书管理

#### 2.1 获取证书列表

```
GET /certificates
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

查询参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| page | int | 否 | 页码，默认1 |
| page_size | int | 否 | 每页记录数，默认20 |
| domain | string | 否 | 域名搜索关键词 |
| status | string | 否 | 证书状态（issued, pending, expired） |
| sort | string | 否 | 排序字段（created_at, valid_to） |
| order | string | 否 | 排序方向（asc, desc） |

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "total": 2,
    "page": 1,
    "page_size": 20,
    "items": [
      {
        "id": 1,
        "domain": "example.com",
        "wildcard": false,
        "ca": "letsencrypt",
        "encryption": "ECC",
        "valid_from": "2025-06-20T06:24:49Z",
        "valid_to": "2025-09-18T06:24:49Z",
        "status": "issued",
        "created_at": "2025-06-20T06:24:49Z",
        "remark": "自动申请"
      },
      {
        "id": 2,
        "domain": "*.example.org",
        "wildcard": true,
        "ca": "zerossl",
        "encryption": "RSA",
        "valid_from": "2025-06-19T06:24:49Z",
        "valid_to": "2025-09-17T06:24:49Z",
        "status": "issued",
        "created_at": "2025-06-19T06:24:49Z",
        "remark": "-"
      }
    ]
  }
}
```

#### 2.2 申请证书

```
POST /certificates
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

请求参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| domain | string | 是 | 域名，支持通配符（如*.example.com） |
| ca | string | 是 | 证书颁发机构（letsencrypt, zerossl, google） |
| encryption | string | 是 | 加密算法（ECC, RSA） |
| remark | string | 否 | 备注信息 |

请求示例：

```json
{
  "domain": "example.com",
  "ca": "letsencrypt",
  "encryption": "ECC",
  "remark": "测试证书"
}
```

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 3,
    "domain": "example.com",
    "wildcard": false,
    "ca": "letsencrypt",
    "encryption": "ECC",
    "status": "pending",
    "dns_records": [
      {
        "type": "TXT",
        "name": "_acme-challenge.example.com",
        "value": "randomvalue123456789",
        "status": "pending"
      }
    ],
    "created_at": "2025-06-20T06:24:49Z",
    "remark": "测试证书"
  }
}
```

#### 2.3 验证域名

```
POST /certificates/{id}/verify
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 证书ID |

响应示例（成功）：

```json
{
  "code": 0,
  "message": "Domain verified successfully",
  "data": {
    "id": 3,
    "domain": "example.com",
    "wildcard": false,
    "ca": "letsencrypt",
    "encryption": "ECC",
    "valid_from": "2025-06-20T06:24:49Z",
    "valid_to": "2025-09-18T06:24:49Z",
    "status": "issued",
    "created_at": "2025-06-20T06:24:49Z",
    "remark": "测试证书"
  }
}
```

响应示例（失败）：

```json
{
  "code": 1006,
  "message": "Domain verification failed: DNS record not found",
  "data": null
}
```

#### 2.4 获取证书详情

```
GET /certificates/{id}
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 证书ID |

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 1,
    "domain": "example.com",
    "wildcard": false,
    "ca": "letsencrypt",
    "encryption": "ECC",
    "valid_from": "2025-06-20T06:24:49Z",
    "valid_to": "2025-09-18T06:24:49Z",
    "status": "issued",
    "created_at": "2025-06-20T06:24:49Z",
    "updated_at": "2025-06-20T06:24:49Z",
    "remark": "自动申请",
    "dns_records": [
      {
        "type": "TXT",
        "name": "_acme-challenge.example.com",
        "value": "randomvalue123456789",
        "status": "verified"
      }
    ]
  }
}
```

#### 2.5 下载证书

```
GET /certificates/{id}/download
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 证书ID |

查询参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| format | string | 否 | 证书格式（nginx, apache, iis, pem, pfx），默认为nginx |

响应：

成功时返回证书文件，Content-Type为application/zip。

#### 2.6 删除证书

```
DELETE /certificates/{id}
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 证书ID |

响应示例：

```json
{
  "code": 0,
  "message": "Certificate deleted successfully",
  "data": null
}
```

#### 2.7 更新证书备注

```
PATCH /certificates/{id}
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 证书ID |

请求参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| remark | string | 是 | 新的备注信息 |

请求示例：

```json
{
  "remark": "新备注信息"
}
```

响应示例：

```json
{
  "code": 0,
  "message": "Certificate updated successfully",
  "data": {
    "id": 1,
    "remark": "新备注信息"
  }
}
```

#### 2.8 批量删除失效证书

```
DELETE /certificates/expired
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

响应示例：

```json
{
  "code": 0,
  "message": "3 expired certificates deleted successfully",
  "data": {
    "count": 3
  }
}
```

### 3. 服务器管理

#### 3.1 获取服务器列表

```
GET /servers
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

查询参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| page | int | 否 | 页码，默认1 |
| page_size | int | 否 | 每页记录数，默认20 |
| name | string | 否 | 服务器名称搜索关键词 |
| type | string | 否 | 服务器类型（nginx, apache） |
| status | string | 否 | 服务器状态（normal, error） |

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "total": 2,
    "page": 1,
    "page_size": 20,
    "items": [
      {
        "id": 1,
        "name": "web-server-1",
        "type": "nginx",
        "system": "CentOS Linux 7 (Core)",
        "ip": "192.168.1.100",
        "version": "1.18.0",
        "status": "normal",
        "auto_deploy": true,
        "last_updated": "2025-06-20T06:24:49Z",
        "remark": "-"
      },
      {
        "id": 2,
        "name": "web-server-2",
        "type": "apache",
        "system": "Ubuntu 20.04 LTS",
        "ip": "192.168.1.101",
        "version": "2.4.41",
        "status": "normal",
        "auto_deploy": false,
        "last_updated": "2025-06-19T06:24:49Z",
        "remark": "测试服务器"
      }
    ]
  }
}
```

#### 3.2 添加服务器

```
POST /servers
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

请求参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| name | string | 是 | 服务器名称 |
| ip | string | 是 | 服务器IP地址 |
| port | int | 否 | SSH端口，默认22 |
| username | string | 是 | SSH用户名 |
| auth_type | string | 是 | 认证类型（password, key） |
| password | string | 否 | SSH密码（auth_type为password时必填） |
| private_key | string | 否 | SSH私钥（auth_type为key时必填） |
| auto_deploy | bool | 否 | 是否自动部署，默认false |
| remark | string | 否 | 备注信息 |

请求示例：

```json
{
  "name": "web-server-3",
  "ip": "192.168.1.102",
  "port": 22,
  "username": "root",
  "auth_type": "password",
  "password": "your_password",
  "auto_deploy": true,
  "remark": "新服务器"
}
```

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 3,
    "name": "web-server-3",
    "ip": "192.168.1.102",
    "status": "pending",
    "auto_deploy": true,
    "created_at": "2025-06-20T06:24:49Z",
    "remark": "新服务器"
  }
}
```

#### 3.3 获取服务器详情

```
GET /servers/{id}
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 服务器ID |

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 1,
    "name": "web-server-1",
    "type": "nginx",
    "system": "CentOS Linux 7 (Core)",
    "ip": "192.168.1.100",
    "port": 22,
    "username": "root",
    "auth_type": "password",
    "version": "1.18.0",
    "status": "normal",
    "auto_deploy": true,
    "created_at": "2025-06-20T06:24:49Z",
    "last_updated": "2025-06-20T06:24:49Z",
    "remark": "-",
    "certificates": [
      {
        "id": 1,
        "domain": "example.com",
        "valid_to": "2025-09-18T06:24:49Z",
        "status": "issued"
      }
    ]
  }
}
```

#### 3.4 更新服务器

```
PUT /servers/{id}
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 服务器ID |

请求参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| name | string | 否 | 服务器名称 |
| port | int | 否 | SSH端口 |
| username | string | 否 | SSH用户名 |
| auth_type | string | 否 | 认证类型（password, key） |
| password | string | 否 | SSH密码（auth_type为password时） |
| private_key | string | 否 | SSH私钥（auth_type为key时） |
| auto_deploy | bool | 否 | 是否自动部署 |
| remark | string | 否 | 备注信息 |

请求示例：

```json
{
  "name": "web-server-1-updated",
  "auto_deploy": false,
  "remark": "已更新"
}
```

响应示例：

```json
{
  "code": 0,
  "message": "Server updated successfully",
  "data": {
    "id": 1,
    "name": "web-server-1-updated",
    "auto_deploy": false,
    "remark": "已更新"
  }
}
```

#### 3.5 删除服务器

```
DELETE /servers/{id}
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 服务器ID |

响应示例：

```json
{
  "code": 0,
  "message": "Server deleted successfully",
  "data": null
}
```

#### 3.6 测试服务器连接

```
POST /servers/{id}/test
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 服务器ID |

响应示例（成功）：

```json
{
  "code": 0,
  "message": "Connection successful",
  "data": {
    "type": "nginx",
    "system": "CentOS Linux 7 (Core)",
    "version": "1.18.0"
  }
}
```

响应示例（失败）：

```json
{
  "code": 1006,
  "message": "Connection failed: timeout",
  "data": null
}
```

### 4. 证书监控

#### 4.1 获取监控列表

```
GET /monitors
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

查询参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| page | int | 否 | 页码，默认1 |
| page_size | int | 否 | 每页记录数，默认20 |
| domain | string | 否 | 域名搜索关键词 |
| status | string | 否 | 状态（normal, warning, error） |
| sort | string | 否 | 排序字段（valid_days, created_at） |
| order | string | 否 | 排序方向（asc, desc） |

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "total": 2,
    "page": 1,
    "page_size": 20,
    "items": [
      {
        "id": 1,
        "domain": "example.com",
        "cert_level": "DV",
        "encryption": "ECC",
        "port": 443,
        "ip_type": "IPv4",
        "ip": "93.184.216.34",
        "status": "normal",
        "valid_days": 90,
        "enabled": true,
        "last_check": "2025-06-20T06:24:49Z",
        "remark": "-"
      },
      {
        "id": 2,
        "domain": "example.org",
        "cert_level": "DV",
        "encryption": "RSA",
        "port": 443,
        "ip_type": "IPv4",
        "ip": "93.184.216.35",
        "status": "warning",
        "valid_days": 15,
        "enabled": true,
        "last_check": "2025-06-20T06:24:49Z",
        "remark": "即将过期"
      }
    ]
  }
}
```

#### 4.2 添加监控

```
POST /monitors
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

请求参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| domain | string | 是 | 域名 |
| port | int | 否 | 端口，默认443 |
| enabled | bool | 否 | 是否启用，默认true |
| remark | string | 否 | 备注信息 |

请求示例：

```json
{
  "domain": "example.net",
  "port": 443,
  "enabled": true,
  "remark": "新监控"
}
```

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 3,
    "domain": "example.net",
    "port": 443,
    "enabled": true,
    "created_at": "2025-06-20T06:24:49Z",
    "remark": "新监控"
  }
}
```

#### 4.3 获取监控详情

```
GET /monitors/{id}
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 监控ID |

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 1,
    "domain": "example.com",
    "cert_level": "DV",
    "encryption": "ECC",
    "port": 443,
    "ip_type": "IPv4",
    "ip": "93.184.216.34",
    "status": "normal",
    "valid_days": 90,
    "enabled": true,
    "created_at": "2025-06-20T06:24:49Z",
    "last_check": "2025-06-20T06:24:49Z",
    "remark": "-",
    "cert_info": {
      "subject": "CN=example.com",
      "issuer": "CN=Let's Encrypt Authority X3",
      "valid_from": "2025-06-20T06:24:49Z",
      "valid_to": "2025-09-18T06:24:49Z",
      "serial": "03:a1:b2:c3:d4:e5:f6:a7:b8:c9:d0:e1:f2:a3:b4:c5",
      "fingerprint": "SHA256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
    },
    "history": [
      {
        "check_time": "2025-06-20T06:24:49Z",
        "status": "normal",
        "valid_days": 90,
        "message": "Certificate is valid"
      },
      {
        "check_time": "2025-06-19T06:24:49Z",
        "status": "normal",
        "valid_days": 91,
        "message": "Certificate is valid"
      }
    ]
  }
}
```

#### 4.4 更新监控

```
PUT /monitors/{id}
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 监控ID |

请求参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| port | int | 否 | 端口 |
| enabled | bool | 否 | 是否启用 |
| remark | string | 否 | 备注信息 |

请求示例：

```json
{
  "enabled": false,
  "remark": "已禁用"
}
```

响应示例：

```json
{
  "code": 0,
  "message": "Monitor updated successfully",
  "data": {
    "id": 1,
    "enabled": false,
    "remark": "已禁用"
  }
}
```

#### 4.5 删除监控

```
DELETE /monitors/{id}
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 监控ID |

响应示例：

```json
{
  "code": 0,
  "message": "Monitor deleted successfully",
  "data": null
}
```

#### 4.6 立即检测

```
POST /monitors/{id}/check
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

路径参数：

| 参数名 | 类型 | 描述 |
|--------|------|------|
| id | int | 监控ID |

响应示例：

```json
{
  "code": 0,
  "message": "Check completed",
  "data": {
    "id": 1,
    "domain": "example.com",
    "status": "normal",
    "valid_days": 90,
    "last_check": "2025-06-20T06:24:49Z",
    "cert_info": {
      "subject": "CN=example.com",
      "issuer": "CN=Let's Encrypt Authority X3",
      "valid_from": "2025-06-20T06:24:49Z",
      "valid_to": "2025-09-18T06:24:49Z"
    }
  }
}
```

### 5. 系统管理

#### 5.1 获取系统状态

```
GET /system/status
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "version": "1.0.0",
    "uptime": "10d 5h 30m",
    "certificates": {
      "total": 10,
      "valid": 8,
      "expired": 1,
      "pending": 1
    },
    "servers": {
      "total": 5,
      "normal": 4,
      "error": 1
    },
    "monitors": {
      "total": 15,
      "normal": 12,
      "warning": 2,
      "error": 1
    },
    "system": {
      "cpu_usage": 15.2,
      "memory_usage": 45.8,
      "disk_usage": 32.6
    }
  }
}
```

#### 5.2 获取系统设置

```
GET /system/settings
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "acme": {
      "default_ca": "letsencrypt",
      "default_encryption": "ECC",
      "renewal_days": 30,
      "staging": false
    },
    "monitor": {
      "check_interval": 86400,
      "warning_threshold": 15,
      "error_threshold": 7
    },
    "notification": {
      "email": {
        "enabled": true,
        "recipients": ["admin@example.com"]
      },
      "webhook": {
        "enabled": false,
        "url": ""
      }
    }
  }
}
```

#### 5.3 更新系统设置

```
PUT /system/settings
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

请求参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| acme | object | 否 | ACME设置 |
| monitor | object | 否 | 监控设置 |
| notification | object | 否 | 通知设置 |

请求示例：

```json
{
  "acme": {
    "default_ca": "zerossl",
    "default_encryption": "ECC",
    "renewal_days": 15
  },
  "monitor": {
    "check_interval": 43200,
    "warning_threshold": 10,
    "error_threshold": 5
  }
}
```

响应示例：

```json
{
  "code": 0,
  "message": "Settings updated successfully",
  "data": {
    "acme": {
      "default_ca": "zerossl",
      "default_encryption": "ECC",
      "renewal_days": 15,
      "staging": false
    },
    "monitor": {
      "check_interval": 43200,
      "warning_threshold": 10,
      "error_threshold": 5
    },
    "notification": {
      "email": {
        "enabled": true,
        "recipients": ["admin@example.com"]
      },
      "webhook": {
        "enabled": false,
        "url": ""
      }
    }
  }
}
```

#### 5.4 获取系统日志

```
GET /system/logs
```

请求头：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

查询参数：

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| page | int | 否 | 页码，默认1 |
| page_size | int | 否 | 每页记录数，默认50 |
| level | string | 否 | 日志级别（info, warn, error） |
| start_time | string | 否 | 开始时间（ISO 8601格式） |
| end_time | string | 否 | 结束时间（ISO 8601格式） |
| keyword | string | 否 | 搜索关键词 |

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "total": 100,
    "page": 1,
    "page_size": 50,
    "items": [
      {
        "id": "log123456",
        "time": "2025-06-20T06:24:49Z",
        "level": "info",
        "module": "certificate",
        "message": "Certificate issued successfully: example.com"
      },
      {
        "id": "log123455",
        "time": "2025-06-20T06:23:49Z",
        "level": "info",
        "module": "server",
        "message": "Server connected: web-server-1 (192.168.1.100)"
      },
      {
        "id": "log123454",
        "time": "2025-06-20T06:22:49Z",
        "level": "warn",
        "module": "monitor",
        "message": "Certificate will expire soon: example.org (15 days)"
      }
    ]
  }
}
```

## 状态码

| 状态码 | 描述 |
|--------|------|
| 0 | 成功 |
| 1000 | 服务器内部错误 |
| 1001 | 认证失败 |
| 1002 | 权限不足 |
| 1003 | 请求参数错误 |
| 1004 | 资源不存在 |
| 1005 | 资源已存在 |
| 1006 | 操作失败 |
| 1007 | 数据库错误 |
| 1008 | 网络错误 |
| 1009 | 第三方服务错误 |
| 1010 | 配置错误 |
| 1011 | 资源限制 |
| 1012 | 请求超时 |
| 1013 | 服务不可用 |
| 1014 | 未知错误 |

## 附录

### 证书状态

| 状态 | 描述 |
|------|------|
| pending | 待验证 |
| issued | 已签发 |
| expired | 已过期 |
| revoked | 已吊销 |
| failed | 签发失败 |

### 服务器状态

| 状态 | 描述 |
|------|------|
| pending | 待连接 |
| normal | 正常 |
| error | 错误 |

### 监控状态

| 状态 | 描述 |
|------|------|
| normal | 正常（有效期大于警告阈值） |
| warning | 警告（有效期小于警告阈值但大于错误阈值） |
| error | 错误（有效期小于错误阈值或已过期） |
| unknown | 未知（无法获取证书信息） |

### 证书颁发机构

| 代码 | 名称 |
|------|------|
| letsencrypt | Let's Encrypt |
| zerossl | ZeroSSL |
| google | Google Trust Services |

### 加密算法

| 代码 | 名称 |
|------|------|
| ECC | 椭圆曲线加密 |
| RSA | RSA加密 |

### 证书等级

| 代码 | 名称 |
|------|------|
| DV | 域名验证 |
| OV | 组织验证 |
| EV | 扩展验证 |
