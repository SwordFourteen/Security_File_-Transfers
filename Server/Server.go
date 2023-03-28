package Server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// 日志 接口
type logger interface {
	Debug(v ...interface{})
	Error(v ...interface{})
}

// 配置 接口
type configer interface {
	QueryPutPath(authArg string) (string, error)
	QueryGetPath(authArg string, pathID string) (string, error)
}

// ErrNotPathID 是QueryGetPath的特指
var ErrNotPathID = errors.New("cpf: not pathID")

// Server is a cpf server
type Server struct {
	// 欢迎 语句
	Welcome  string
	listener net.Listener
	cfg      configer
	log      logger

	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	auth         func(string) bool
	// CA 证书和私钥
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
}

// NewServer 创建新的server并且握手
func NewServer(cfg configer, log logger) *Server {
	s := &Server{
		Welcome: "Welcome to cpf",

		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
		IdleTimeout:  time.Minute * 5,
		//获取CA证书等
		caCert: loadCACertificate(),
		caKey:  loadCAPrivateKey(),
	}

	if cfg == nil {
		s.cfg = def
	} else {
		s.cfg = cfg
	}

	if log == nil {
		s.log = def
	} else {
		s.log = log
	}

	return s
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
