package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Security_File_-Transfers/tools"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"time"
)

const serverAddress string = "localhost:8080" //服务器地址
const clientAddress string = "localhost:8983" //c
const Maxconn int = 3                         //最大连接数
// Client is  connect
type Client struct {
	address string
	name    string
	conn    []net.Conn //连接池用于并行
	buf     []byte     // 先定义一个buf
	priKey  rsa.PrivateKey
	myCert  *x509.Certificate
	key     cipher.Block //临时证书
}

func main() {
	var mainWindow *walk.MainWindow
	//var openFileDialog *walk.FileDialog
	var userInfoEdit *walk.LineEdit

	//openFileDialog = new(walk.FileDialog)
	my_Client := new(Client)
	my_Client.address = clientAddress
	my_Client.name = "0"
	my_Client.conn = make([]net.Conn, Maxconn)
	// 创建链接
	err := my_Client.newConnect(serverAddress, 1)
	if err != nil {
		panic(err)
	}

	go my_Client.receiveconn(1)
	MainWindow{
		AssignTo: &mainWindow,
		Title:    "安全文件传输系统",
		MinSize:  Size{Width: 300, Height: 200},
		Layout:   VBox{},
		Children: []Widget{
			Label{
				Text: "User Info:",
			},
			LineEdit{
				AssignTo: &userInfoEdit,
			},
			// 发送证书验证
			PushButton{
				Text: "提交证书申请，请输入客户端名称",
				OnClicked: func() {
					my_Client.name = userInfoEdit.Text()      //客户端名称
					my_Client.SubmmitCsr(userInfoEdit.Text()) //提交证书申请
					walk.MsgBox(mainWindow, "Success", "提交证书申请成功!", walk.MsgBoxIconInformation)

				},
			},
			PushButton{
				Text: "建立链接",
				OnClicked: func() {
					if my_Client.name == "0" {
						walk.MsgBox(mainWindow, "建立链接失败请检查是否存在证书", err.Error(), walk.MsgBoxIconError)
					} else {
						my_Client.handleRequst(tools.Open, []byte("Hello"))
					}

				},
			},
			PushButton{
				Text: "获取文件目录",
				OnClicked: func() {
					// 获取文件目录逻辑
					my_Client.handleRequst(tools.GetFileList, nil)
				},
			},
			PushButton{
				Text: "发送文件",
				OnClicked: func() {
					var fileName string
					InputBox(
						mainWindow,
						"发送文件",
						"请输入文件名:",
						&fileName,
					)
					// 使用输入的文件名发送文件的逻辑
					my_Client.sendFile(fileName)
				},
			},
			PushButton{
				Text: "获取文件",
				OnClicked: func() {
					var fileName string
					InputBox(
						mainWindow,
						"获取文件",
						"请输入文件名:",
						&fileName,
					)
					my_Client.handleRequst(tools.GetFile, nil)

				},
			},

			PushButton{
				Text: "删除文件",
				OnClicked: func() {
					var fileName string

					InputBox(
						mainWindow,
						"删除文件",
						"请输入要删除的文件名:",
						&fileName,
					)
					// 使用输入的文件名删除文件的逻辑
					my_Client.handleRequst(tools.DeleteFile, []byte(fileName))
				},
			},
		},
	}.Run()

}

// newConnect 长链接
func (c *Client) newConnect(serverAddress string, id int) error {
	// 与服务器建立 TCP 连接

	conn, err := net.Dial("tcp", serverAddress)
	if err != nil {
		return fmt.Errorf("unable to connect to server: %v", err)
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		fmt.Println("Connection is not a *net.TCPConn")
	}
	// 设置 Keepalive
	err = tcpConn.SetKeepAlive(true)
	// 设置 Keepalive 时间间隔（可选）
	err = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	if err != nil {
		fmt.Println("Error setting Keepalive period:", err)
	}
	c.conn[id] = tcpConn
	return nil
}

// 监听链接数据
func (c *Client) receiveconn(id int) {
	for {
		println("我在等待接收")
		var packet tools.DataPacket
		err := json.NewDecoder(c.conn[id]).Decode(&packet)
		if err != nil {
			fmt.Printf("Error reading data from server: %v\n", err)
			break
		}
		// 根据接收到的数据包内容处理具体业务逻辑
		c.handleDataPacket(packet)
	}
}

// handleRequst  处理客户端的发送
func (c *Client) handleRequst(flag tools.Flag, byt []byte) error {
	switch flag {
	//请求证书
	case tools.RequestCert:
		// 将字节切片转换为 Base64 编码的字符串
		contentBase64 := base64.StdEncoding.EncodeToString(byt)
		len := uint32(len(contentBase64))
		packet := tools.DataPacket{
			Flag:          tools.RequestCert,
			FileName:      "",
			PacketCount:   0,
			CurrentPacket: 0,
			PacketSize:    0,
			Nowsize:       len,
			Content:       contentBase64,
			Signature:     "",
		}
		by, err := json.Marshal(packet)
		if err != nil {
			panic(err)
		}
		c.conn[1].Write(by)

		// 添加一个换行符
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			panic(err)
		}
	// 建立链接认证
	case tools.Open:
		// 将字节切片转换为 Base64 编码的字符串
		contentBase64 := base64.StdEncoding.EncodeToString(byt)
		len := uint32(len(contentBase64))
		packet := tools.DataPacket{
			Flag:          tools.Open,
			FileName:      "",
			PacketCount:   0,
			CurrentPacket: 0,
			PacketSize:    0,
			Nowsize:       len,
			Content:       contentBase64,
			Signature:     "",
		}
		by, err := json.Marshal(packet)
		if err != nil {
			panic(err)
		}
		c.conn[1].Write(by)
		// 添加一个换行符
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			panic(err)
		}
	//获取文件列表
	case tools.GetFileList:
		packet := tools.DataPacket{
			Flag:          tools.GetFileList,
			Certname:      "",
			FileName:      "",
			PacketCount:   0,
			CurrentPacket: 0,
			PacketSize:    0,
			Nowsize:       0,
			Content:       "",
			Signature:     "",
		}
		packetByte, err := json.Marshal(packet)
		if err != nil {
			panic("序列化失败")
		}
		c.conn[1].Write(packetByte)
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			panic(err)
		}
	//删除文件
	case tools.DeleteFile:
		packet := tools.DataPacket{
			Flag:          tools.DeleteFile,
			Certname:      "",
			FileName:      string(byt),
			PacketCount:   0,
			CurrentPacket: 0,
			PacketSize:    0,
			Nowsize:       0,
			Content:       "",
			Signature:     "",
		}
		packetByte, err := json.Marshal(packet)
		if err != nil {
			panic("序列化失败")
		}
		c.conn[1].Write(packetByte)
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			panic(err)
		}
	}

	return nil
}

// handleDataPacket 处理收到的请求
func (c *Client) handleDataPacket(packet tools.DataPacket) {

	switch packet.Flag {
	case tools.ReRequestCert:
		cert, err := base64.StdEncoding.DecodeString(packet.Content)
		if err != nil {
			panic("客户端解析证书错误")
		}
		certBlock, _ := pem.Decode(cert)
		if certBlock == nil {
			panic("客户端解析证书错误：PEM 解码失败")
		}

		c.myCert, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			panic("客户端解析证书错误：证书解析失败")
		}

		os.WriteFile("./"+c.name+"/"+c.name+".crt", certBlock.Bytes, 0644)
		println("生成证书成功")
	case tools.Open:
		//发来的是ca的证书
		if packet.FileName == "cert" {
			encryptedKeyBase64 := base64.StdEncoding.EncodeToString(c.myCert.Raw)
			newpacket := tools.DataPacket{
				Flag:          tools.Open,
				FileName:      "cert",
				PacketCount:   0,
				CurrentPacket: 0,
				PacketSize:    0,
				Nowsize:       uint32(len(c.myCert.Raw)),
				Content:       encryptedKeyBase64,
				Signature:     "",
			}
			writebyte, err := json.Marshal(newpacket)
			if err != nil {
				panic("发送证书失败")
			}
			c.conn[1].Write(writebyte)
			println("发送证书成功")
			_, err = c.conn[1].Write([]byte("\x1e"))
			if err != nil {
				panic(err)
			}
		}

		//发来的是随机数
		if packet.FileName == "key" {
			//生成的随机数,现在还被客户端的公钥加密,需要私钥解密
			random, err := base64.StdEncoding.DecodeString(packet.Content)
			decryptedRandomKey, err := rsa.DecryptPKCS1v15(rand.Reader, &c.priKey, random)
			if err != nil {
				panic("解密随机数失败")
			}
			// 使用解密后的随机数创建对称密钥
			block, err := aes.NewCipher(decryptedRandomKey)
			c.key = block //对称密钥
			if err != nil {
				panic("创建对称密钥失败")
			}
			println("生成对称密钥成功")
			// 加密字符串 "finish"
			plaintext := []byte("finish")
			ciphertext := make([]byte, len(plaintext))

			// 使用对称密钥进行加密
			stream := cipher.NewCTR(c.key, make([]byte, c.key.BlockSize()))
			stream.XORKeyStream(ciphertext, plaintext)

			// 对加密后的字符串进行 base64 编码
			encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

			// 创建一个新的 DataPacket，并设置 Content 为加密后的 "finish" 字符串
			finishPacket := tools.DataPacket{
				Flag:          tools.Open,
				FileName:      "finish",
				PacketCount:   0,
				CurrentPacket: 0,
				PacketSize:    0,
				Nowsize:       uint32(len(ciphertext)),
				Content:       encodedCiphertext,
				Signature:     "", // 如果需要签名，请在此处设置
			}
			// 序列化 DataPacket 为 JSON
			packetBytes, err := json.Marshal(finishPacket)
			if err != nil {
				panic("序列化 finishPacket 失败")
			}
			// 将 "finish" 消息发送给客户端
			_, err = c.conn[1].Write(packetBytes)
			_, err = c.conn[1].Write([]byte("\x1e"))
			if err != nil {
				panic(err)
			}
			if err != nil {
				panic("发送加密后的 'finish' 消息失败")
			}
			println("发送加密后的 'finish' 消息成功")
		}

		if packet.FileName == "finish" {
			println("成功建立安全链接")
		}
	case tools.GetFileList:
		var fileDirWindow *walk.MainWindow
		var fileDirEdit *walk.TextEdit
		MainWindow{
			AssignTo: &fileDirWindow,
			Title:    "文件目录",
			MinSize:  Size{Width: 400, Height: 300},
			Layout:   VBox{},
			Children: []Widget{
				TextEdit{
					AssignTo: &fileDirEdit,
					ReadOnly: true,
					Text:     packet.Content, // 替换为从服务器获取的文件目录
				},
			},
		}.Run()
	default:
		fmt.Println("收到未知的Flag:", packet.Flag)
	}

}

// sendFile 发送文件
func (c *Client) sendFile(filePath string) error {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// 获取文件信息
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	// 计算数据包数量
	packetCount := uint32(math.Ceil(float64(fileInfo.Size()) / float64(tools.MaxContentSize)))

	// 逐个读取文件内容并发送
	for i := uint32(0); i < packetCount; i++ {
		// 读取文件内容
		buf := make([]byte, tools.MaxContentSize)
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		// 使用对称密钥加密文件内容
		blockSize := c.key.BlockSize()
		cipherText := make([]byte, n)
		stream := cipher.NewCTR(c.key, make([]byte, blockSize))
		stream.XORKeyStream(cipherText, buf[:n])

		// 创建数据包
		packet := tools.DataPacket{
			Flag:          tools.SendFile,
			FileName:      filepath.Base(filePath),
			PacketCount:   packetCount,
			CurrentPacket: i,
			PacketSize:    uint32(n),
			Nowsize:       0,
			Content:       base64.StdEncoding.EncodeToString(cipherText),
			Signature:     "",
		}

		// 序列化数据包为 JSON
		packetBytes, err := json.Marshal(packet)
		if err != nil {
			return err
		}

		// 发送数据包
		_, err = c.conn[1].Write(packetBytes)
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			panic(err)
		}
		if err != nil {
			return err
		}
		// 添加一个换行符
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			return err
		}
	}

	return nil
}

// SubmmitCsr 输入名字IP签发证书,给Client自己私钥
func (c *Client) SubmmitCsr(name string) {
	//判断是否存在私钥
	if _, err := os.Stat("./" + name); os.IsNotExist(err) {
		os.Mkdir("./"+name, 0644)
		PrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		c.priKey = *PrivKey
		if err != nil {
			panic(err)
		}
		priPEM := new(bytes.Buffer)
		pem.Encode(priPEM, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(PrivKey),
		})
		os.WriteFile("./"+name+"/"+name+".key", priPEM.Bytes(), 0644)
		//保存完本地私钥开始传递证书申请
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{
				Country:            []string{"CN"},
				Province:           []string{"Beijing"},
				Locality:           []string{"Beijing"},
				Organization:       []string{"GKD"},
				OrganizationalUnit: []string{"GKD"},
				CommonName:         name,
			},
			PublicKey: PrivKey.PublicKey,
		}
		//创建请求
		csrByte, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, PrivKey)
		//创建PEM块
		csrPEM := new(bytes.Buffer)
		pem.Encode(csrPEM, &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrByte,
		})
		c.handleRequst(tools.RequestCert, csrPEM.Bytes())
		println(csrTemplate.Subject.CommonName)
		if err != nil {
			panic(err)
		}
	}
}

func loadCACertificate(filePath string) *x509.Certificate {
	certPEM, err := os.ReadFile(filePath)
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
func loadCAPrivateKey(filePath string) *rsa.PrivateKey {
	keyPEM, err := os.ReadFile(filePath)
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

func InputBox(owner walk.Form, title, message string, fileName *string) (int, error) {
	var dialog *walk.Dialog
	var acceptPB, cancelPB *walk.PushButton
	var input *walk.LineEdit

	return Dialog{
		AssignTo:      &dialog,
		Title:         title,
		DefaultButton: &acceptPB,
		CancelButton:  &cancelPB,
		MinSize:       Size{Width: 300, Height: 200},
		Layout:        VBox{},
		Children: []Widget{
			Label{
				Text: message,
			},
			LineEdit{
				AssignTo: &input,
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						AssignTo:  &acceptPB,
						Text:      "确定",
						OnClicked: func() { *fileName = input.Text(); dialog.Accept() },
					},
					PushButton{
						AssignTo:  &cancelPB,
						Text:      "取消",
						OnClicked: func() { dialog.Cancel() },
					},
				},
			},
		},
	}.Run(owner)
}
