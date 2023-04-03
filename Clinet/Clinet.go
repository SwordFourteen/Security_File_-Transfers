package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"net"
	"time"
)

var serverAddress string = "localhost:8080" //服务器地址
var clientAddress string = "localgost:8088" //c
// Client is  connect
type Client struct {
	address string
	welcome string
	conn    net.Conn
	reader  *bufio.Reader
	buf     []byte // 先定义一个buf
}

func main() {
	var mainWindow *walk.MainWindow
	var openFileDialog *walk.FileDialog
	var userInfoEdit *walk.LineEdit

	openFileDialog = new(walk.FileDialog)
	my_Client := new(Client)
	my_Client.address = clientAddress

	// 创建链接
	go func() {
		err := my_Client.newConnect(serverAddress)
		if err != nil {
			panic(err)
		}
	}()
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
			PushButton{
				Text: "提交证书申请，请输入你的姓名",
				OnClicked: func() {
					var ipSlice []net.IP
					ipSlice = append(ipSlice, net.ParseIP(clientAddress))
					my_Client.newConnect(serverAddress)
					my_Client.SubmmitCsr(userInfoEdit.Text(), ipSlice) //提交证书申请
					walk.MsgBox(mainWindow, "Success", "提交证书申请成功!", walk.MsgBoxIconInformation)

				},
			},
			PushButton{
				Text: "建立链接",
				OnClicked: func() {
					if _, err := openFileDialog.ShowOpen(mainWindow); err == nil {
						if err != nil {
							walk.MsgBox(mainWindow, "建立链接失败请检查延时或证书", err.Error(), walk.MsgBoxIconError)
						} else {
							walk.MsgBox(mainWindow, "Success", "建立长连接成功!", walk.MsgBoxIconInformation)
						}
					}
				},
			},
			PushButton{
				Text:      "发送文件",
				OnClicked: nil,
			},
			PushButton{
				Text:      "获取文件目录",
				OnClicked: nil,
			},
			PushButton{
				Text:      "获取文件",
				OnClicked: nil,
			},
			PushButton{
				Text:      "删除文件",
				OnClicked: nil,
			},
		},
	}.Run()

}

// newConnect 长链接
func (c *Client) newConnect(serverAddress string) error {
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
	c.conn = conn
	return nil
}

// sendFile 发送文件
func (c *Client) sendFile(serverAddress, filePath string) error {
	return nil
}

// SubmmitCsr 输入名字IP签发证书
func (c *Client) SubmmitCsr(name string, IP []net.IP) {
	PrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Province:           []string{"Beijing"},
			Locality:           []string{"Beijing"},
			Organization:       []string{"GKD"},
			OrganizationalUnit: []string{"GKD"},
			CommonName:         name,
		},
		IPAddresses: IP,
		PublicKey:   PrivKey.PublicKey,
	}
	//创建请求
	csrByte, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, PrivKey)
	//创建PEM块
	csrPEM := new(bytes.Buffer)
	pem.Encode(csrPEM, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrByte,
	})

	println(csrTemplate.Subject.CommonName)
	if err != nil {
		panic(err)
	}

}
