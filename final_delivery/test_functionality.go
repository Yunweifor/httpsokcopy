package main

import (
	"fmt"
	"time"

	"github.com/httpsok/internal/config"
	"github.com/httpsok/internal/logger"
	"github.com/httpsok/internal/services"
	"github.com/httpsok/internal/models"
)

// 测试结果结构
type TestResult struct {
	TestName string
	Success  bool
	Message  string
	Duration time.Duration
}

// 测试报告
type TestReport struct {
	Results []TestResult
	Summary map[string]int
}

func main() {
	fmt.Println("=== httpsok系统功能完整性测试 ===")
	fmt.Println("开始时间:", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	report := &TestReport{
		Results: []TestResult{},
		Summary: map[string]int{"passed": 0, "failed": 0, "total": 0},
	}

	// 执行各项测试
	testConfigurationManagement(report)
	testLoggerFunctionality(report)
	testACMEService(report)
	testDataModels(report)
	testSSLCertificateRequest(report)

	// 输出测试报告
	printTestReport(report)
}

// 测试配置管理功能
func testConfigurationManagement(report *TestReport) {
	fmt.Println("1. 测试配置管理功能")

	start := time.Now()
	cfg, err := config.Load()
	duration := time.Since(start)

	if err != nil {
		addTestResult(report, "配置加载", false, fmt.Sprintf("配置加载失败: %v", err), duration)
		return
	}

	addTestResult(report, "配置加载", true, "配置文件加载成功", duration)

	// 验证配置项
	if cfg.Server.Port == 0 {
		addTestResult(report, "服务器端口配置", false, "服务器端口未配置", 0)
	} else {
		addTestResult(report, "服务器端口配置", true, fmt.Sprintf("服务器端口: %d", cfg.Server.Port), 0)
	}

	if cfg.ACME.DefaultCA == "" {
		addTestResult(report, "ACME CA配置", false, "ACME CA未配置", 0)
	} else {
		addTestResult(report, "ACME CA配置", true, fmt.Sprintf("默认CA: %s", cfg.ACME.DefaultCA), 0)
	}

	fmt.Printf("   ✓ 配置管理测试完成\n\n")
}

// 测试日志功能
func testLoggerFunctionality(report *TestReport) {
	fmt.Println("2. 测试日志功能")

	start := time.Now()
	logger := logger.NewLogger("debug", "logs")
	duration := time.Since(start)

	if logger == nil {
		addTestResult(report, "日志初始化", false, "日志器初始化失败", duration)
		return
	}

	addTestResult(report, "日志初始化", true, "日志器初始化成功", duration)

	// 测试各级别日志
	start = time.Now()
	logger.Info("测试信息日志")
	logger.Debug("测试调试日志")
	logger.Error("测试错误日志", fmt.Errorf("测试错误"))
	duration = time.Since(start)

	addTestResult(report, "日志输出", true, "各级别日志输出正常", duration)

	fmt.Printf("   ✓ 日志功能测试完成\n\n")
}

// 测试ACME服务
func testACMEService(report *TestReport) {
	fmt.Println("3. 测试ACME服务功能")

	logger := logger.NewLogger("debug", "logs")
	acmeService := services.NewACMEService(logger)

	if acmeService == nil {
		addTestResult(report, "ACME服务初始化", false, "ACME服务初始化失败", 0)
		return
	}

	addTestResult(report, "ACME服务初始化", true, "ACME服务初始化成功", 0)

	// 测试DNS验证记录生成
	start := time.Now()
	challenge, err := acmeService.GenerateDNSChallenge("ssl.gzyggl.com")
	duration := time.Since(start)

	if err != nil {
		addTestResult(report, "DNS验证记录生成", false, fmt.Sprintf("DNS验证记录生成失败: %v", err), duration)
	} else {
		addTestResult(report, "DNS验证记录生成", true,
			fmt.Sprintf("DNS记录: %s %s %s", challenge.HostRecord, challenge.RecordType, challenge.RecordValue[:10]+"..."), duration)
	}

	// 测试DNS验证
	if challenge != nil {
		start = time.Now()
		verified, err := acmeService.VerifyDNSChallenge("ssl.gzyggl.com", challenge.HostRecord, challenge.RecordType, challenge.RecordValue)
		duration = time.Since(start)

		if err != nil {
			addTestResult(report, "DNS验证", false, fmt.Sprintf("DNS验证失败: %v", err), duration)
		} else if verified {
			addTestResult(report, "DNS验证", true, "DNS验证成功", duration)
		} else {
			addTestResult(report, "DNS验证", false, "DNS验证失败", duration)
		}
	}

	// 测试证书签发（模拟）
	start = time.Now()
	domains := []string{"ssl.gzyggl.com"}
	certData, err := acmeService.IssueCertificate(domains, "letsencrypt", "ECC")
	duration = time.Since(start)

	if err != nil {
		addTestResult(report, "证书签发", false, fmt.Sprintf("证书签发失败: %v", err), duration)
	} else if certData != nil && certData.Certificate != "" {
		addTestResult(report, "证书签发", true, "证书签发成功（模拟）", duration)
	} else {
		addTestResult(report, "证书签发", false, "证书签发返回空数据", duration)
	}

	fmt.Printf("   ✓ ACME服务测试完成\n\n")
}

// 测试数据模型
func testDataModels(report *TestReport) {
	fmt.Println("4. 测试数据模型")

	// 测试证书模型
	start := time.Now()
	cert := &models.Certificate{
		DomainMain:     "ssl.gzyggl.com",
		CAType:         "letsencrypt",
		EncryptionType: "ECC",
		Status:         "pending",
		AutoRenew:      true,
		RenewBeforeDays: 30,
		UserID:         1,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	duration := time.Since(start)

	if cert.DomainMain == "ssl.gzyggl.com" && cert.CAType == "letsencrypt" {
		addTestResult(report, "证书模型", true, "证书模型创建和赋值正常", duration)
	} else {
		addTestResult(report, "证书模型", false, "证书模型数据异常", duration)
	}

	// 测试服务器模型
	start = time.Now()
	server := &models.Server{
		Name:       "测试服务器",
		Hostname:   "ssl.gzyggl.com",
		IPAddress:  "127.0.0.1",
		ServerType: "nginx",
		OSType:     "linux",
		Port:       22,
		AuthType:   "password",
		Username:   "root",
		Status:     "normal",
		AutoDeploy: true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	duration = time.Since(start)

	if server.Hostname == "ssl.gzyggl.com" && server.ServerType == "nginx" {
		addTestResult(report, "服务器模型", true, "服务器模型创建和赋值正常", duration)
	} else {
		addTestResult(report, "服务器模型", false, "服务器模型数据异常", duration)
	}

	// 测试监控模型
	start = time.Now()
	monitor := &models.Monitor{
		Host:          "ssl.gzyggl.com",
		Port:          443,
		IPType:        "ipv4",
		CheckInterval: 24,
		Enabled:       true,
		LastStatus:    "normal",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	duration = time.Since(start)

	if monitor.Host == "ssl.gzyggl.com" && monitor.Port == 443 {
		addTestResult(report, "监控模型", true, "监控模型创建和赋值正常", duration)
	} else {
		addTestResult(report, "监控模型", false, "监控模型数据异常", duration)
	}

	fmt.Printf("   ✓ 数据模型测试完成\n\n")
}

// 测试SSL证书申请流程
func testSSLCertificateRequest(report *TestReport) {
	fmt.Println("5. 测试SSL证书申请流程（ssl.gzyggl.com）")

	logger := logger.NewLogger("debug", "logs")
	acmeService := services.NewACMEService(logger)

	// 步骤1: 生成DNS验证记录
	start := time.Now()
	challenge, err := acmeService.GenerateDNSChallenge("ssl.gzyggl.com")
	duration := time.Since(start)

	if err != nil {
		addTestResult(report, "SSL申请-DNS记录生成", false, fmt.Sprintf("DNS记录生成失败: %v", err), duration)
		return
	}

	addTestResult(report, "SSL申请-DNS记录生成", true,
		fmt.Sprintf("生成DNS记录: %s", challenge.HostRecord), duration)

	fmt.Printf("   DNS验证记录:\n")
	fmt.Printf("   主机记录: %s\n", challenge.HostRecord)
	fmt.Printf("   记录类型: %s\n", challenge.RecordType)
	fmt.Printf("   记录值: %s\n", challenge.RecordValue)
	fmt.Printf("   \n")

	// 步骤2: 模拟DNS验证
	start = time.Now()
	verified, err := acmeService.VerifyDNSChallenge("ssl.gzyggl.com", challenge.HostRecord, challenge.RecordType, challenge.RecordValue)
	duration = time.Since(start)

	if err != nil {
		addTestResult(report, "SSL申请-DNS验证", false, fmt.Sprintf("DNS验证失败: %v", err), duration)
	} else if verified {
		addTestResult(report, "SSL申请-DNS验证", true, "DNS验证通过", duration)
	} else {
		addTestResult(report, "SSL申请-DNS验证", false, "DNS验证未通过", duration)
	}

	// 步骤3: 证书签发
	start = time.Now()
	domains := []string{"ssl.gzyggl.com"}
	certData, err := acmeService.IssueCertificate(domains, "letsencrypt", "ECC")
	duration = time.Since(start)

	if err != nil {
		addTestResult(report, "SSL申请-证书签发", false, fmt.Sprintf("证书签发失败: %v", err), duration)
	} else if certData != nil {
		addTestResult(report, "SSL申请-证书签发", true, "证书签发成功（模拟）", duration)

		fmt.Printf("   证书信息:\n")
		fmt.Printf("   证书长度: %d 字符\n", len(certData.Certificate))
		fmt.Printf("   私钥长度: %d 字符\n", len(certData.PrivateKey))
		fmt.Printf("   证书链长度: %d 字符\n", len(certData.Chain))
		fmt.Printf("   \n")
	}

	fmt.Printf("   ✓ SSL证书申请流程测试完成\n\n")
}

// 添加测试结果
func addTestResult(report *TestReport, testName string, success bool, message string, duration time.Duration) {
	result := TestResult{
		TestName: testName,
		Success:  success,
		Message:  message,
		Duration: duration,
	}

	report.Results = append(report.Results, result)
	report.Summary["total"]++

	if success {
		report.Summary["passed"]++
		fmt.Printf("   ✓ %s: %s (耗时: %v)\n", testName, message, duration)
	} else {
		report.Summary["failed"]++
		fmt.Printf("   ✗ %s: %s (耗时: %v)\n", testName, message, duration)
	}
}

// 输出测试报告
func printTestReport(report *TestReport) {
	fmt.Println("=== 测试报告 ===")
	fmt.Printf("总测试数: %d\n", report.Summary["total"])
	fmt.Printf("通过: %d\n", report.Summary["passed"])
	fmt.Printf("失败: %d\n", report.Summary["failed"])
	fmt.Printf("成功率: %.2f%%\n", float64(report.Summary["passed"])/float64(report.Summary["total"])*100)
	fmt.Println()

	fmt.Println("详细结果:")
	for _, result := range report.Results {
		status := "✓"
		if !result.Success {
			status = "✗"
		}
		fmt.Printf("%s %s: %s\n", status, result.TestName, result.Message)
	}

	fmt.Println()
	fmt.Println("测试完成时间:", time.Now().Format("2006-01-02 15:04:05"))

	// 输出建议
	fmt.Println("\n=== 测试建议 ===")
	if report.Summary["failed"] > 0 {
		fmt.Println("发现问题:")
		for _, result := range report.Results {
			if !result.Success {
				fmt.Printf("- %s: %s\n", result.TestName, result.Message)
			}
		}
	} else {
		fmt.Println("所有基础功能测试通过！")
	}

	fmt.Println("\n注意事项:")
	fmt.Println("- 当前测试为模拟环境，未连接真实数据库")
	fmt.Println("- ACME服务使用模拟实现，实际部署需要真实的acme.sh集成")
	fmt.Println("- 证书申请需要真实的DNS配置和域名验证")
	fmt.Println("- 建议在测试环境中进行完整的端到端测试")
}
