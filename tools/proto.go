package tools

import (
	"io/ioutil"
	"os"
)

type Flag uint32

const (
	RequestCert Flag = iota // 请求证书: 0
	Open                    // 建立长连接: 1
	SendFile                // 发送文件: 2
	GetFileList             // 获取文件目录: 3
	GetFile                 // 获取文件: 4
	DeleteFile              // 删除文件: 5
)
const (
	MaxContentSize = 1048576 //1MB
)

type DataPacket struct {
	Flag          Flag                 `json:"flag"`
	FileName      string               `json:"file_name"`
	PacketCount   uint32               `json:"packet_count"`
	CurrentPacket uint32               `json:"current_packet"`
	PacketSize    uint32               `json:"packet_size"`
	Content       [MaxContentSize]byte `json:"content"`
	Signature     string               `json:"signature"`
}

func CreateDataPackets(filePath string, flag Flag, signature string) ([]DataPacket, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := fileInfo.Size()
	packetCount := fileSize / MaxContentSize
	if fileSize%MaxContentSize != 0 {
		packetCount++
	}

	dataPackets := make([]DataPacket, packetCount)
	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	for i := range dataPackets {
		start := int64(i) * MaxContentSize
		end := start + MaxContentSize
		if end > fileSize {
			end = fileSize
		}

		var content [MaxContentSize]byte
		copy(content[:], fileContent[start:end])

		dataPackets[i] = DataPacket{
			Flag:          flag,
			FileName:      fileInfo.Name(),
			PacketCount:   uint32(packetCount),
			CurrentPacket: uint32(i),
			PacketSize:    uint32(end - start),
			Content:       content,
			Signature:     signature,
		}
	}
	return dataPackets, nil
}

func Requst(flag Flag) {

}
