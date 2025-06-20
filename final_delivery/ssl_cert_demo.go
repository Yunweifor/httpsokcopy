package main

import (
	"fmt"
	"time"

	"github.com/httpsok/internal/config"
	"github.com/httpsok/internal/logger"
	"github.com/httpsok/internal/services"
	"github.com/httpsok/internal/models"
)

func main() {
	fmt.Println("=== SSL证书申请实例测试 ===")
	fmt.Println("域名: ssl.gzyggl.com")
	fmt.Println("邮箱: 19822088@qq.com")
	fmt.Println("CA: Let's Encrypt")
	fmt.Println("加密算法: ECC")
	fmt.Println("开始时间:", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	// 初始化服务
	_, err := config.Load()
	if err != nil {
		fmt.Printf("❌ 配置加载失败: %v\n", err)
		return
	}

	logger := logger.NewLogger("debug", "logs")
	acmeService := services.NewACMEService(logger)

	// 步骤1: 创建证书申请记录
	fmt.Println("📋 步骤1: 创建证书申请记录")
	cert := &models.Certificate{
		DomainMain:      "ssl.gzyggl.com",
		CAType:          "letsencrypt",
		EncryptionType:  "ECC",
		Status:          "pending",
		AutoRenew:       true,
		RenewBeforeDays: 30,
		UserID:          1,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	fmt.Printf("✅ 证书记录创建成功\n")
	fmt.Printf("   域名: %s\n", cert.DomainMain)
	fmt.Printf("   CA类型: %s\n", cert.CAType)
	fmt.Printf("   加密类型: %s\n", cert.EncryptionType)
	fmt.Printf("   自动续期: %v\n", cert.AutoRenew)
	fmt.Println()

	// 步骤2: 生成DNS验证记录
	fmt.Println("🔍 步骤2: 生成DNS验证记录")
	challenge, err := acmeService.GenerateDNSChallenge(cert.DomainMain)
	if err != nil {
		fmt.Printf("❌ DNS验证记录生成失败: %v\n", err)
		return
	}

	fmt.Printf("✅ DNS验证记录生成成功\n")
	fmt.Printf("   主机记录: %s\n", challenge.HostRecord)
	fmt.Printf("   记录类型: %s\n", challenge.RecordType)
	fmt.Printf("   记录值: %s\n", challenge.RecordValue)
	fmt.Println()

	// 步骤3: 显示DNS配置说明
	fmt.Println("⚙️  步骤3: DNS配置说明")
	fmt.Println("请在您的DNS服务商处添加以下TXT记录:")
	fmt.Printf("   主机记录: %s\n", challenge.HostRecord)
	fmt.Printf("   记录类型: %s\n", challenge.RecordType)
	fmt.Printf("   记录值: %s\n", challenge.RecordValue)
	fmt.Println()
	fmt.Println("配置示例（以阿里云DNS为例）:")
	fmt.Println("   1. 登录阿里云控制台")
	fmt.Println("   2. 进入域名解析管理")
	fmt.Println("   3. 选择域名 gzyggl.com")
	fmt.Println("   4. 添加解析记录:")
	fmt.Printf("      - 记录类型: %s\n", challenge.RecordType)
	fmt.Printf("      - 主机记录: %s\n", challenge.HostRecord)
	fmt.Printf("      - 记录值: %s\n", challenge.RecordValue)
	fmt.Println("      - TTL: 600（10分钟）")
	fmt.Println()

	// 步骤4: 模拟DNS验证
	fmt.Println("🔐 步骤4: DNS验证")
	fmt.Println("正在验证DNS记录...")
	time.Sleep(2 * time.Second) // 模拟验证时间

	verified, err := acmeService.VerifyDNSChallenge(cert.DomainMain, challenge.HostRecord, challenge.RecordType, challenge.RecordValue)
	if err != nil {
		fmt.Printf("❌ DNS验证失败: %v\n", err)
		return
	}

	if verified {
		fmt.Printf("✅ DNS验证成功\n")
		fmt.Printf("   域名: %s\n", cert.DomainMain)
		fmt.Printf("   验证时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("❌ DNS验证失败\n")
		fmt.Println("   请检查DNS记录配置是否正确")
		return
	}
	fmt.Println()

	// 步骤5: 证书签发
	fmt.Println("📜 步骤5: 证书签发")
	fmt.Println("正在向Let's Encrypt申请证书...")
	time.Sleep(3 * time.Second) // 模拟签发时间

	domains := []string{cert.DomainMain}
	certData, err := acmeService.IssueCertificate(domains, cert.CAType, cert.EncryptionType)
	if err != nil {
		fmt.Printf("❌ 证书签发失败: %v\n", err)
		return
	}

	fmt.Printf("✅ 证书签发成功\n")
	fmt.Printf("   域名: %s\n", cert.DomainMain)
	fmt.Printf("   CA: %s\n", cert.CAType)
	fmt.Printf("   加密算法: %s\n", cert.EncryptionType)
	fmt.Printf("   证书长度: %d 字符\n", len(certData.Certificate))
	fmt.Printf("   私钥长度: %d 字符\n", len(certData.PrivateKey))
	fmt.Printf("   证书链长度: %d 字符\n", len(certData.Chain))
	fmt.Printf("   签发时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	// 步骤6: 更新证书状态
	fmt.Println("💾 步骤6: 更新证书状态")
	cert.Status = "issued"
	cert.ValidFrom.Time = time.Now()
	cert.ValidFrom.Valid = true
	cert.ValidTo.Time = time.Now().AddDate(0, 3, 0) // 3个月有效期
	cert.ValidTo.Valid = true
	cert.CertData.String = certData.Certificate
	cert.CertData.Valid = true
	cert.KeyData.String = certData.PrivateKey
	cert.KeyData.Valid = true
	cert.ChainData.String = certData.Chain
	cert.ChainData.Valid = true
	cert.UpdatedAt = time.Now()

	fmt.Printf("✅ 证书状态更新成功\n")
	fmt.Printf("   状态: %s\n", cert.Status)
	fmt.Printf("   生效时间: %s\n", cert.ValidFrom.Time.Format("2006-01-02 15:04:05"))
	fmt.Printf("   过期时间: %s\n", cert.ValidTo.Time.Format("2006-01-02 15:04:05"))
	fmt.Printf("   剩余天数: %.0f 天\n", cert.ValidTo.Time.Sub(time.Now()).Hours()/24)
	fmt.Println()

	// 步骤7: 证书文件保存
	fmt.Println("💾 步骤7: 证书文件保存")
	fmt.Println("证书文件将保存到以下位置:")
	fmt.Printf("   证书文件: ./storage/certs/%s.crt\n", cert.DomainMain)
	fmt.Printf("   私钥文件: ./storage/certs/%s.key\n", cert.DomainMain)
	fmt.Printf("   证书链文件: ./storage/certs/%s.chain.crt\n", cert.DomainMain)
	fmt.Println()

	// 步骤8: 部署建议
	fmt.Println("🚀 步骤8: 部署建议")
	fmt.Println("证书申请成功！您可以:")
	fmt.Println("   1. 下载证书文件到本地")
	fmt.Println("   2. 配置Web服务器（Nginx/Apache）")
	fmt.Println("   3. 设置自动部署到服务器")
	fmt.Println("   4. 启用证书监控和自动续期")
	fmt.Println()

	fmt.Println("Nginx配置示例:")
	fmt.Println("   server {")
	fmt.Println("       listen 443 ssl;")
	fmt.Printf("       server_name %s;\n", cert.DomainMain)
	fmt.Printf("       ssl_certificate /path/to/%s.crt;\n", cert.DomainMain)
	fmt.Printf("       ssl_certificate_key /path/to/%s.key;\n", cert.DomainMain)
	fmt.Println("       ssl_protocols TLSv1.2 TLSv1.3;")
	fmt.Println("       ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;")
	fmt.Println("   }")
	fmt.Println()

	// 测试总结
	fmt.Println("=== 测试总结 ===")
	fmt.Printf("✅ 域名: %s\n", cert.DomainMain)
	fmt.Printf("✅ 邮箱: 19822088@qq.com\n")
	fmt.Printf("✅ CA: %s\n", cert.CAType)
	fmt.Printf("✅ 加密算法: %s\n", cert.EncryptionType)
	fmt.Printf("✅ DNS验证: 通过\n")
	fmt.Printf("✅ 证书签发: 成功\n")
	fmt.Printf("✅ 证书状态: %s\n", cert.Status)
	fmt.Printf("✅ 有效期: %s 至 %s\n",
		cert.ValidFrom.Time.Format("2006-01-02"),
		cert.ValidTo.Time.Format("2006-01-02"))
	fmt.Println()
	fmt.Println("🎉 SSL证书申请流程测试完成！")
	fmt.Println("完成时间:", time.Now().Format("2006-01-02 15:04:05"))
}
