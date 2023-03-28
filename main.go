package main

import (
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func main() {
	var inTE *walk.TextEdit
	var outTE *walk.TextEdit

	MainWindow{
		Title:   "文件传输工具",
		MinSize: Size{600, 400},
		Layout:  VBox{},
		Children: []Widget{
			GroupBox{
				Title:  "选择文件",
				Layout: HBox{},
				Children: []Widget{
					PushButton{
						Text: "选择文件",
						OnClicked: func() {
							dlg := new(walk.FileDialog)
							dlg.Title = "选择文件"
							dlg.Filter = "All Files (*.*)|*.*"

							if ok, err := dlg.ShowOpen(walk.App().ActiveForm()); err != nil {
								walk.MsgBox(walk.App().ActiveForm(), "Error", err.Error(), walk.MsgBoxIconError)
								return
							} else if !ok {
								return
							}
							inTE.SetText(dlg.FilePath)
						},
					},
					TextEdit{AssignTo: &inTE},
				},
			},
			GroupBox{
				Title:  "操作",
				Layout: HBox{},
				Children: []Widget{
					PushButton{
						Text: "发送文件",
						OnClicked: func() {
							// 在这里实现发送文件的功能
							outTE.AppendText("发送文件: " + inTE.Text() + "\r\n")
						},
					},
					PushButton{
						Text: "获取文件",
						OnClicked: func() {
							// 在这里实现获取文件的功能
							outTE.AppendText("获取文件: " + inTE.Text() + "\r\n")
						},
					},
					PushButton{
						Text: "提交证书申请",
						OnClicked: func() {
							// 在这里实现提交证书申请的功能
							outTE.AppendText("提交证书申请\r\n")
						},
					},
				},
			},
			GroupBox{
				Title:  "日志输出",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &outTE, ReadOnly: true, VScroll: true},
				},
			},
		},
	}.Run()

}
