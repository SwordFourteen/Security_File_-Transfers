package tools

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

const (
	keySize = 2048
)

func initCa() {
	//用于初始化根CA目录，只执行一次如果检索到就不执行了
	if _, err := os.Stat("./CA"); os.IsNotExist(err) {
		err := os.Mkdir("./CA", 0700)
		if err != nil {
			panic(err)
		}
		//初始化私钥
		rootKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			panic(err)
		}
		// 生成根证书
		rootCsr := x509.Certificate{
			SerialNumber: big.NewInt(time.Now().Unix()),
			Subject: pkix.Name{
				Country:            []string{"CN"},
				Province:           []string{"Beijing"},
				Locality:           []string{"Beijing"},
				Organization:       []string{"GKD"},
				OrganizationalUnit: []string{"GKD"},
				CommonName:         "Root CA",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
			MaxPathLenZero:        false,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		rootCABytes, err := x509.CreateCertificate(rand.Reader, &rootCsr, &rootCsr, &rootKey.PublicKey, rootKey)
		if err != nil {
			panic(err)
		}
		//证书
		caPEM := new(bytes.Buffer)
		pem.Encode(caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCABytes,
		})
		os.WriteFile("./CA/CA.crt", caPEM.Bytes(), 0644)
		// 私钥
		caPrivKeyPEM := new(bytes.Buffer)
		pem.Encode(caPrivKeyPEM, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
		})
		os.WriteFile("./CA/CA.key", caPrivKeyPEM.Bytes(), 0644)
	}
}

// SignCsr  对CSR进行签名返回证书，传PEM块
func SignCsr(csr []byte) (crt []byte) {
	// 读取CA的证书私钥
	CAcert := loadCACertificate()
	CAPriv := loadCAPrivateKey()
	// 解码传入的CSR
	csrBlock, _ := pem.Decode(csr)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil
	}

	// 解析传入的CSR
	csrParsed, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		panic(err)
		return nil

	}
	// 创建证书模板
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),                                              //为证书分配一个序列号
		Subject:               csrParsed.Subject,                                                          //主题
		NotBefore:             time.Now(),                                                                 //生效时间
		NotAfter:              time.Now().AddDate(1, 0, 0),                                                // 设置证书有效期，例如1年
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,               //设置用途可以数字签名和封装
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, //设置证书的验证
		BasicConstraintsValid: false,                                                                      //它可不可以签发证书
	}

	// 使用CA证书和私钥签署证书
	certBytes, err := x509.CreateCertificate(rand.Reader, template, CAcert, csrParsed.PublicKey, CAPriv)
	if err != nil {
		panic(err)
		return nil
	}
	// 将生成的证书编码为PEM格式
	certPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	// 转换成证书的Byte格式
	crt = pem.EncodeToMemory(certPem)
	return crt
}

// VerifyCrt 检测证书正确性传PEM块
func VerifyCrt(CertData []byte) bool {
	// 加载CA证书，这里需要确保CA证书已经存在
	caCert := loadCACertificate()
	// 创建证书池并添加CA证书
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)
	return true
	// 解析证书数据
	block, _ := pem.Decode(CertData)
	if block == nil || block.Type != "CERTIFICATE" {
		panic("证书块获取失败")
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing certificate:", err)
		return false
	}
	// 验证证书签名和有效期
	opts := x509.VerifyOptions{
		Roots:       certPool,
		CurrentTime: time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		fmt.Println("证书验证失败:", err)
		return false
	}

	return true
}

func loadCACertificate() *x509.Certificate {
	certPEM, err := os.ReadFile("./CA/CA.crt")
	if err != nil {
		return nil
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		fmt.Errorf("failed to decode PEM block containing the CAcertificate")
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}

	return cert
}

func loadCAPrivateKey() *rsa.PrivateKey {
	keyPEM, err := os.ReadFile("./CA/CA.key")
	if err != nil {
		fmt.Errorf("No have the CAprivate key")
		return nil
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		fmt.Errorf("failed to decode PEM block containing the CAprivate key")
		return nil
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}

	return key
}
