package main

import (
	"fmt"
	"log"
	"os"
	"testing"
	"time"
	"net/http"
	"encoding/json"
	"bytes"
)

// 测试配置
var (
	baseURL = "http://localhost:8080/api/v1"
	testUser = map[string]string{
		"username": "testuser",
		"password": "Test@123",
	}
	authToken = ""
)

// 测试主函数
func TestMain(m *testing.M) {
	// 设置测试环境
	setup()
	
	// 运行测试
	code := m.Run()
	
	// 清理测试环境
	teardown()
	
	// 退出
	os.Exit(code)
}

// 设置测试环境
func setup() {
	fmt.Println("=== 设置测试环境 ===")
	
	// 等待API服务启动
	waitForAPIService()
	
	// 获取认证令牌
	getAuthToken()
}

// 清理测试环境
func teardown() {
	fmt.Println("=== 清理测试环境 ===")
	// 清理测试数据
}

// 等待API服务启动
func waitForAPIService() {
	fmt.Println("等待API服务启动...")
	maxRetries := 10
	retryInterval := 2 * time.Second
	
	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(baseURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			fmt.Println("API服务已启动")
			return
		}
		
		fmt.Printf("API服务未就绪，%d秒后重试...\n", int(retryInterval.Seconds()))
		time.Sleep(retryInterval)
	}
	
	log.Fatal("API服务启动超时")
}

// 获取认证令牌
func getAuthToken() {
	fmt.Println("获取认证令牌...")
	
	// 准备请求数据
	jsonData, _ := json.Marshal(testUser)
	
	// 发送请求
	resp, err := http.Post(baseURL+"/auth/login", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("登录请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	// 解析响应
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("解析响应失败: %v", err)
	}
	
	// 提取令牌
	if token, ok := result["data"].(map[string]interface{})["token"].(string); ok {
		authToken = token
		fmt.Println("认证令牌获取成功")
	} else {
		log.Fatal("获取认证令牌失败")
	}
}

// 测试用户认证
func TestAuthentication(t *testing.T) {
	t.Run("登录成功", func(t *testing.T) {
		// 准备请求数据
		jsonData, _ := json.Marshal(testUser)
		
		// 发送请求
		resp, err := http.Post(baseURL+"/auth/login", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			t.Fatalf("登录请求失败: %v", err)
		}
		defer resp.Body.Close()
		
		// 验证状态码
		if resp.StatusCode != http.StatusOK {
			t.Errorf("预期状态码 %d，实际状态码 %d", http.StatusOK, resp.StatusCode)
		}
		
		// 解析响应
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("解析响应失败: %v", err)
		}
		
		// 验证响应
		if success, ok := result["success"].(bool); !ok || !success {
			t.Errorf("预期登录成功，实际失败: %v", result)
		}
	})
	
	t.Run("登录失败-密码错误", func(t *testing.T) {
		// 准备请求数据
		invalidUser := map[string]string{
			"username": testUser["username"],
			"password": "wrongpassword",
		}
		jsonData, _ := json.Marshal(invalidUser)
		
		// 发送请求
		resp, err := http.Post(baseURL+"/auth/login", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			t.Fatalf("登录请求失败: %v", err)
		}
		defer resp.Body.Close()
		
		// 验证状态码
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("预期状态码 %d，实际状态码 %d", http.StatusUnauthorized, resp.StatusCode)
		}
	})
}

// 测试证书管理
func TestCertificateManagement(t *testing.T) {
	t.Run("获取证书列表", func(t *testing.T) {
		// 创建请求
		req, _ := http.NewRequest("GET", baseURL+"/certificates", nil)
		req.Header.Add("Authorization", "Bearer "+authToken)
		
		// 发送请求
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("获取证书列表请求失败: %v", err)
		}
		defer resp.Body.Close()
		
		// 验证状态码
		if resp.StatusCode != http.StatusOK {
			t.Errorf("预期状态码 %d，实际状态码 %d", http.StatusOK, resp.StatusCode)
		}
		
		// 解析响应
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("解析响应失败: %v", err)
		}
		
		// 验证响应
		if success, ok := result["success"].(bool); !ok || !success {
			t.Errorf("预期请求成功，实际失败: %v", result)
		}
		
		// 验证数据结构
		if _, ok := result["data"].(map[string]interface{})["certificates"]; !ok {
			t.Errorf("响应缺少certificates字段: %v", result)
		}
	})
	
	t.Run("创建证书", func(t *testing.T) {
		// 准备请求数据
		certData := map[string]interface{}{
			"domain": "test.example.com",
			"ca_type": "letsencrypt",
			"encryption_type": "ECC",
			"notes": "测试证书",
		}
		jsonData, _ := json.Marshal(certData)
		
		// 创建请求
		req, _ := http.NewRequest("POST", baseURL+"/certificates", bytes.NewBuffer(jsonData))
		req.Header.Add("Authorization", "Bearer "+authToken)
		req.Header.Add("Content-Type", "application/json")
		
		// 发送请求
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("创建证书请求失败: %v", err)
		}
		defer resp.Body.Close()
		
		// 验证状态码
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			t.Errorf("预期状态码 %d 或 %d，实际状态码 %d", http.StatusCreated, http.StatusOK, resp.StatusCode)
		}
	})
}

// 测试服务器管理
func TestServerManagement(t *testing.T) {
	t.Run("获取服务器列表", func(t *testing.T) {
		// 创建请求
		req, _ := http.NewRequest("GET", baseURL+"/servers", nil)
		req.Header.Add("Authorization", "Bearer "+authToken)
		
		// 发送请求
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("获取服务器列表请求失败: %v", err)
		}
		defer resp.Body.Close()
		
		// 验证状态码
		if resp.StatusCode != http.StatusOK {
			t.Errorf("预期状态码 %d，实际状态码 %d", http.StatusOK, resp.StatusCode)
		}
		
		// 解析响应
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("解析响应失败: %v", err)
		}
		
		// 验证响应
		if success, ok := result["success"].(bool); !ok || !success {
			t.Errorf("预期请求成功，实际失败: %v", result)
		}
		
		// 验证数据结构
		if _, ok := result["data"].(map[string]interface{})["servers"]; !ok {
			t.Errorf("响应缺少servers字段: %v", result)
		}
	})
}

// 测试证书监控
func TestCertificateMonitoring(t *testing.T) {
	t.Run("获取监控列表", func(t *testing.T) {
		// 创建请求
		req, _ := http.NewRequest("GET", baseURL+"/monitors", nil)
		req.Header.Add("Authorization", "Bearer "+authToken)
		
		// 发送请求
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("获取监控列表请求失败: %v", err)
		}
		defer resp.Body.Close()
		
		// 验证状态码
		if resp.StatusCode != http.StatusOK {
			t.Errorf("预期状态码 %d，实际状态码 %d", http.StatusOK, resp.StatusCode)
		}
		
		// 解析响应
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("解析响应失败: %v", err)
		}
		
		// 验证响应
		if success, ok := result["success"].(bool); !ok || !success {
			t.Errorf("预期请求成功，实际失败: %v", result)
		}
		
		// 验证数据结构
		if _, ok := result["data"].(map[string]interface{})["monitors"]; !ok {
			t.Errorf("响应缺少monitors字段: %v", result)
		}
	})
}

// 测试健康检查
func TestHealthCheck(t *testing.T) {
	// 发送请求
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("健康检查请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	// 验证状态码
	if resp.StatusCode != http.StatusOK {
		t.Errorf("预期状态码 %d，实际状态码 %d", http.StatusOK, resp.StatusCode)
	}
	
	// 解析响应
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	
	// 验证响应
	if status, ok := result["status"].(string); !ok || status != "ok" {
		t.Errorf("预期状态 'ok'，实际状态 %v", status)
	}
}
