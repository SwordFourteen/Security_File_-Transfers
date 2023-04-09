package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Security_File_-Transfers/tools"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
)

const FilePath = "./File"

var goID int = 0 //线程ID
const severhost = "localhost:8080"

type FileInfo struct {
	Name string
	Size int64
}

// Server 服务器对象
type Server struct {
	listener  net.Listener
	buffer    []tools.DataPacket          //文件包
	fileCache map[string][]byte           //守护进程线程池
	certPool  map[string]x509.Certificate //用于储存已经认证的证书
	// CA 证书和私钥
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	ket    cipher.Block //临时的对称密钥
}

// NewServer 创建新的server并且监听握手
func main() {
	server := new(Server)
	server.fileCache = make(map[string][]byte)
	//读取ca信息
	server.caCert = loadCACertificate()
	server.caKey = loadCAPrivateKey()
	//初始化服务器监听器
	err := server.Start(severhost)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}

}

// Start 初始化监听器
func (s *Server) Start(address string) (err error) {

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

		go s.handleDataPacket(conn) //处理连接
	}
}

// handleDataPacket 处理发来的消息
func (s *Server) handleDataPacket(conn net.Conn) {
	//持续读取
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\x1e')
		if err != nil {
			if err == io.EOF {
				fmt.Println("Connection closed")
			} else {
				fmt.Printf("Error reading data from server: %v\n", err)
			}
			break
		}
		line = line[:len(line)-1]
		var packet tools.DataPacket
		err = json.Unmarshal([]byte(line), &packet)
		if err != nil {
			fmt.Printf("Error decoding JSON data: %v\n", err)
			continue
		}

		// 根据接收到的数据包内容处理具体业务逻辑
		switch packet.Flag {
		//返回认证证书
		case tools.RequestCert:
			//解码base64
			contentbyte, err := base64.StdEncoding.DecodeString(packet.Content)
			// 从 DataPacket 的 Content 字段中解析 CSR PEM
			csrBlock, _ := pem.Decode(contentbyte)
			//比较是否接受完全
			if uint32(len(packet.Content)) != packet.Nowsize {
				fmt.Println("Error 解析 CSR PEM block")
				println("解析的长度为" + string(len(packet.Content)))
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
			certByte := tools.SignCsr(contentbyte)
			//初始化消息包
			content := base64.StdEncoding.EncodeToString(certByte)
			newpacket := tools.DataPacket{
				Flag:          tools.ReRequestCert,
				FileName:      "",
				PacketCount:   0,
				CurrentPacket: 0,
				PacketSize:    0,
				Nowsize:       uint32(len(certByte)),
				Content:       content,
				Signature:     "",
			}
			writebyte, err := json.Marshal(newpacket)
			if err != nil {
				panic("返回证书失败")
			}
			println("序列化证书成功" + string(writebyte))
			conn.Write(writebyte)
			println("写成功")
		//处理链接认证
		case tools.Open:
			//解码base64
			contentbyte, err := base64.StdEncoding.DecodeString(packet.Content)
			if err != nil {
				panic("解析Open出错")
			}
			//如果是打招呼
			if string(contentbyte) == "Hello" {
				certByte := loadCACertificate().Raw
				content := base64.StdEncoding.EncodeToString(certByte)
				newpacket := tools.DataPacket{
					Flag:          tools.Open,
					FileName:      "cert",
					PacketCount:   0,
					CurrentPacket: 0,
					PacketSize:    0,
					Nowsize:       uint32(len(certByte)),
					Content:       content,
					Signature:     "",
				}
				writebyte, err := json.Marshal(newpacket)
				if err != nil {
					panic("验证返回Sever证书失败")
				}
				conn.Write(writebyte)
			}
			//如果发来的是证书，验证成功返回由Client公钥加密的随机数
			if packet.FileName == "cert" {
				//解码base64
				contentbyte, err := base64.StdEncoding.DecodeString(packet.Content)
				if err != nil {
					panic("解码失败")
				}
				//解析证书
				cert, err := x509.ParseCertificate(contentbyte)
				if err != nil {
					panic("解析证书失败")
				}
				//验证证书成功发送随机数用于生成对称密钥
				if tools.VerifyCrt(contentbyte) == true {

					// 从证书中提取公钥
					publicKey := cert.PublicKey.(*rsa.PublicKey)

					// 生成随机数
					randomKey := make([]byte, 32) // 假设使用 256 位对称密钥
					if _, err := io.ReadFull(rand.Reader, randomKey); err != nil {
						panic("生成随机数失败")
					}

					// 使用公钥加密随机数
					encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, randomKey)
					if err != nil {
						panic("加密随机数失败")
					}

					// 创建对称密钥
					block, err := aes.NewCipher(randomKey)
					s.ket = block
					if err != nil {
						panic("创建对称密钥失败")
					}

					// 发送加密后的随机数
					encryptedKeyBase64 := base64.StdEncoding.EncodeToString(encryptedKey)
					newpacket := tools.DataPacket{
						Flag:          tools.Open,
						FileName:      "key",
						PacketCount:   0,
						CurrentPacket: 0,
						PacketSize:    0,
						Nowsize:       uint32(len(encryptedKey)),
						Content:       encryptedKeyBase64,
						Signature:     "",
					}
					writebyte, err := json.Marshal(newpacket)
					if err != nil {
						panic("验证返回随机数失败")
					}
					conn.Write(writebyte)
					println("验证返回随机数成功")
				}
			}
			//如果发来的是对称密钥的随机数加密后的
			if packet.FileName == "finish" {
				// 解码 base64
				contentByte, err := base64.StdEncoding.DecodeString(packet.Content)
				if err != nil {
					panic("Base64 解码失败")
				}
				// 解密消息
				decrypted := make([]byte, len(contentByte))
				stream := cipher.NewCTR(s.ket, make([]byte, s.ket.BlockSize()))
				stream.XORKeyStream(decrypted, contentByte)
				// 检查解密后的消息是否为 "finish"
				if string(decrypted) == "finish" {
					// 创建一个新的 DataPacket，设置 FileName 为 "finish"
					finishPacket := tools.DataPacket{
						Flag:          tools.Open, // 使用适当的标志
						FileName:      "finish",
						PacketCount:   0,
						CurrentPacket: 0,
						PacketSize:    0,
						Nowsize:       0,
						Content:       "",
						Signature:     "",
					}

					// 序列化 DataPacket 为 JSON
					writeByte, err := json.Marshal(finishPacket)
					if err != nil {
						panic("序列化 finishPacket 失败")
					}
					// 向服务器发送 "finish" 消息
					conn.Write(writeByte)
					println("收到finish")
				}
			}
		//处理发来的文件
		case tools.SendFile:
			// 解密文件内容
			cipherText, err := base64.StdEncoding.DecodeString(packet.Content)
			if err != nil {
				panic(err)
			}
			blockSize := s.ket.BlockSize()
			plainText := make([]byte, len(cipherText))
			stream := cipher.NewCTR(s.ket, make([]byte, blockSize))
			stream.XORKeyStream(plainText, cipherText)
			// 将解密后的文件内容追加到缓存中
			s.fileCache[packet.FileName] = append(s.fileCache[packet.FileName], plainText...)
			// 检查是否接收到了所有数据包
			if packet.CurrentPacket+1 == packet.PacketCount {
				// 打开或创建文件
				savePath := filepath.Join("./File", packet.FileName)
				file, err := os.OpenFile(savePath, os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					panic(err)
				}

				// 将文件内容写入文件
				_, err = file.Write(s.fileCache[packet.FileName])
				if err != nil {
					panic(err)
				}
				file.Close()
				// 清空缓存
				delete(s.fileCache, packet.FileName)
			}
		//获取文件目录
		case tools.GetFileList:
			File, err := ReadFileDir("./File")
			if err != nil {
				panic(err)
			}
			var Stri string
			for key, _ := range File {
				Stri += File[key].String()
			}
			println(Stri)
			packet := tools.DataPacket{
				Flag:          tools.GetFileList,
				Certname:      "",
				FileName:      "",
				PacketCount:   0,
				CurrentPacket: 0,
				PacketSize:    0,
				Nowsize:       0,
				Content:       Stri,
				Signature:     "",
			}
			byte1, _ := json.Marshal(packet)
			conn.Write(byte1)
		//删除文件
		case tools.DeleteFile:
			os.Remove(FilePath + "/" + packet.FileName)
			println("删除成功")
		default:
			fmt.Println("未知的Flag:", packet.Flag)
		}
	}

}

func (s *Server) hadleRequst(flag tools.Flag, packet tools.DataPacket) {

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

func ReadFileDir(path string) ([]FileInfo, error) {
	var filesInfo []FileInfo

	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			fileInfo, err := d.Info()
			if err != nil {
				return err
			}
			filesInfo = append(filesInfo, FileInfo{
				Name: fileInfo.Name(),
				Size: fileInfo.Size(),
			})
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return filesInfo, nil
}
func (fi FileInfo) String() string {
	return fmt.Sprintf("文件名: %s, 大小: %d 字节\n", fi.Name, fi.Size)
}
