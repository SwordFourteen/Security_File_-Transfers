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

func init() {
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

// 对证书进行签名
func SignCsr(csr x, key rsa.PrivateKey) (crt []byte) {
	// 读取CA的证书私钥
	CAcert, _ := loadCACertificate()
	CAPriv, _ := loadCAPrivateKey()
	certBytes, err := x509.CreateCertificate(rand.Reader, &cert, CAcert, key, CAPriv)
	if err != nil {
		return err
	}
}
func VerifyCrt(CertData []byte) bool {
	/*
		// 解码 PEM 编码的证书数据
		block, _ := pem.Decode(CertData)
		if block == nil {
			panic("failed to decode server certificate")
		}

		// 解析证书数据
		serverCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}

		// 验证证书
		_, err = serverCert.Verify(x509.VerifyOptions{
			//Roots: caCertPool,
		})
		if err != nil {
			panic(err)
		}
	*/
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
