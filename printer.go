package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// Printer 结构体用于封装所有打印相关的功能
type Printer struct{}

// NewPrinter 创建一个新的 Printer 实例
func NewPrinter() *Printer {
	return &Printer{}
}

// PrintAppList 打印应用程序列表
func (p *Printer) PrintAppList(ctx context.Context, apps map[string]*App, checkStatus func(context.Context, *App) (bool, int, bool)) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "Status", "PID", "Managed By"})
	table.SetBorder(false)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")

	for _, app := range apps {
		isRunning, pid, isManagedByKenv := checkStatus(ctx, app)
		status := color.RedString("Not Running")
		pidStr := "-"
		managedBy := "-"
		if isRunning {
			status = color.GreenString("Running")
			pidStr = strconv.Itoa(pid)
			if isManagedByKenv {
				managedBy = color.CyanString("kenv")
			} else {
				managedBy = color.YellowString("External")
			}
		}
		table.Append([]string{app.Name, status, pidStr, managedBy})
	}
	table.Render()
}

// PrintAppStatus 打印应用程序状态
func (p *Printer) PrintAppStatus(app *App, isRunning bool, pid int, isManagedByKenv bool, ports []string, nginxConfig string, procInfo string, multipleApps bool) {
	var processInfo strings.Builder
	var criticalInfo strings.Builder

	color.Cyan("应用程序: %s\n", app.Name)
	fmt.Fprintf(&processInfo, "命令: %s %s\n", app.Executable, app.Args)

	if isRunning {
		fmt.Fprintf(&criticalInfo, "状态: %s\n", color.GreenString("运行中"))
		fmt.Fprintf(&criticalInfo, "PID: %d\n", pid)
		if isManagedByKenv {
			fmt.Fprintf(&criticalInfo, "管理者: %s\n", color.CyanString("kenv"))
		} else {
			fmt.Fprintf(&criticalInfo, "管理者: %s\n", color.YellowString("外部进程"))
		}

		if len(ports) > 0 {
			fmt.Fprintf(&criticalInfo, "内部监听端口: %s\n", strings.Join(ports, ", "))
		} else {
			fmt.Fprintf(&processInfo, "未找到监听端口\n")
		}

		externalPorts := parseNginxConfig(nginxConfig)
		if len(externalPorts) > 0 {
			fmt.Fprintf(&criticalInfo, "外部监听端口:\n")
			for _, ep := range externalPorts {
				fmt.Fprintf(&criticalInfo, "  - %s (%s) -> %s\n", ep.Port, ep.Protocol, ep.ServerName)
			}
		} else {
			fmt.Fprintf(&criticalInfo, "未找到外部监听端口\n")
		}

		fmt.Fprintf(&processInfo, "进程详情:\n%s", procInfo)
		fmt.Fprintf(&criticalInfo, "\n-- 相关Nginx 配置 --\n%s\n", nginxConfig)
	} else {
		fmt.Fprintf(&criticalInfo, "状态: %s\n", color.RedString("未运行"))
	}

	if multipleApps {
		// 只打印关键信息
		fmt.Print(criticalInfo.String())
	} else {
		// 打印所有信息
		fmt.Print(processInfo.String())
		color.Yellow("\n--- 关键信息 ---\n")
		fmt.Print(criticalInfo.String())
	}
}

// PrintError print error info
func (p *Printer) PrintError(format string, a ...interface{}) {
	color.Red(format, a...)
}

// PrintSuccess 打印成功信息
func (p *Printer) PrintSuccess(format string, a ...interface{}) {
	color.Green(format, a...)
}

// PrintInfo print info
func (p *Printer) PrintInfo(format string, a ...interface{}) {
	color.Blue(format, a...)
}

// PrintVerbose print verbose info
func (p *Printer) PrintVerbose(format string, a ...interface{}) {
	gray := color.New(color.FgHiBlack).SprintfFunc()
	fmt.Print(gray(format, a...))
}

// PrintSeparator print separator
func (p *Printer) PrintSeparator() {
	fmt.Println(strings.Repeat("-", 50))
}
