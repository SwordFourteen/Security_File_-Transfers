package tools

type Flag uint32

const (
	RequestCert   Flag = iota // 请求证书:
	ReRequestCert             // 返回证书
	Open                      // 建立长连接:
	SendFile                  // 发送文件:
	GetFileList               // 获取文件目录:
	GetFile                   // 获取文件:
	DeleteFile                // 删除文件:
)
const (
	MaxContentSize = 104857 //1MB
)

type DataPacket struct {
	Flag          Flag   `json:"flag"`
	Certname      string `json:"certname"`
	FileName      string `json:"file_name"`
	PacketCount   uint32 `json:"packet_count"`
	CurrentPacket uint32 `json:"current_packet"`
	PacketSize    uint32 `json:"packet_size"`
	Nowsize       uint32 `json:"nowsize"`
	Content       string `json:"content"`
	Signature     string `json:"EOF"`
}
