package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/Security_File_-Transfers/tools"
	"net"
)

const FilePath = "./File"

var goID int = 0 //线程ID

// Server 服务器对象
type Server struct {
	// 欢迎 语句
	listener      net.Listener
	buffer        []tools.DataPacket            //文件包
	activeDaemons map[string]context.CancelFunc //守护进程线程池
	// CA 证书和私钥
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
}

// NewServer 创建新的server并且握手
func main() {
	server := new(Server)
	err := server.Start("localhost:8080")
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}

func (s *Server) Start(address string) error {
	var err error
	s.listener, err = net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer s.listener.Close()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go s.handleConnection(conn) //处理连接
	}
}

func (s *Server) handleDataPacket(conn net.Conn, packet *tools.DataPacket) {
	switch packet.Flag {
	case tools.RequestCert:
		// 从 DataPacket 的 Content 字段中解析 CSR PEM
		csrBlock, _ := pem.Decode(packet.Content[:])
		if csrBlock == nil {
			fmt.Println("Error decoding CSR PEM block")
			return
		}

		// 解析 CSR 数据
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			fmt.Println("Error parsing CSR:", err)
			return
		}

		// 验证 CSR
		err = csr.CheckSignature()
		if err != nil {
			fmt.Println("Error checking CSR signature:", err)
			return
		}

		// 处理 CSR，签发证书等
		// ...

	default:
		fmt.Println("Unsupported flag:", packet.Flag)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// ... 发送欢迎消息等 ...

	//reader := bufio.NewReader(conn)
}

func (s *Server) handleLongConnection(conn net.Conn) {
	// 为每个长连接创建一个唯一的ID
	connID := string(goID)
	goID++
	// 创建一个Context，用于控制守护进程的生命周期
	ctx, cancel := context.WithCancel(context.Background())
	s.activeDaemons[connID] = cancel

	// 创建守护进程goroutine来处理长连接
	go func() {
		defer func() {
			// 当守护进程结束时，清理资源
			conn.Close()
			delete(s.activeDaemons, connID)
		}()
		for {
			select {
			case <-ctx.Done():
				// 当 context 被取消时，结束守护进程
				return
			default:
				// 在这里处理长连接的业务逻辑
				// ...
			}
		}
	}()
}
func (s *Server) StopLongConnection(connID string) {
	if cancel, ok := s.activeDaemons[connID]; ok {
		cancel()
	}
}
