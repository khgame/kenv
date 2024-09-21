package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/khicago/wlog"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// ListApps 列出所有正在运行的应用程序
func (am *AppManager) ListApps() {
	log := wlog.Common("list_apps")
	am.mu.Lock()
	defer am.mu.Unlock()
	log.Tracef("正在列出所有应用\n")
	for name, app := range am.Apps {
		isRunning, pid, isManagedByKenv := am.checkProcessStatus(app)
		log.Tracef("应用 %s: 运行状态=%v, PID=%d, 由kenv管理=%v\n", name, isRunning, pid, isManagedByKenv)
	}
	am.printer.PrintSeparator()
	am.printer.PrintAppList(am.Apps, am.checkProcessStatus)
	am.printer.PrintSeparator()
}

// checkProcessStatus 检查进程状态
func (am *AppManager) checkProcessStatus(app *App) (isRunning bool, pid int, isManagedByKenv bool) {
	log := wlog.Common("check_process_status")
	log.Tracef("检查应用 %s 的进程状态\n", app.Name)

	if app.Pid != 0 {
		log.Tracef("存储的 PID: %d, 正在验证...\n", app.Pid)
		if am.verifyProcessCommand(app.Pid, app.Executable) {
			log.Tracef("应用 %s 的进程 (PID: %d) 仍在运行\n", app.Name, app.Pid)
			return true, app.Pid, true
		}
		log.Tracef("存储的 PID %d 无效，清理脏数据\n", app.Pid)
		app.Pid = 0 // 清理脏数据
	}

	pid, err := FindProcessByName(app.Name, app.Executable, app.Args)
	if err == nil && pid != 0 {
		log.Tracef("找到应用 %s 的新进程 (PID: %d)\n", app.Name, pid)
		app.Pid = pid // 更新 App 结构体中的 Pid
		return true, pid, false
	}

	log.Tracef("未找到应用 %s 的运行进程\n", app.Name)
	return false, 0, false
}

// 新增方法：验证进程命令
func (am *AppManager) verifyProcessCommand(pid int, expectedExecutable string) bool {
	log := wlog.Common("verify_process_command")
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	output, err := cmd.Output()
	if err != nil {
		log.Tracef("无法获取 PID %d 的命令: %v\n", pid, err)
		return false
	}

	actualCommand := strings.TrimSpace(string(output))
	expectedCommand := filepath.Base(expectedExecutable)

	log.Tracef("PID %d 的实际命令: %s, 期望命令: %s\n", pid, actualCommand, expectedCommand)
	return actualCommand == expectedCommand
}

// StartApp 启动指定的应用程序
func (am *AppManager) StartApp(ctx context.Context, name string) error {
	log := wlog.From(ctx, "start_app")
	am.mu.Lock()
	defer am.mu.Unlock()
	app, ok := am.Apps[name]
	if !ok {
		return fmt.Errorf("app %s not found", name)
	}

	isRunning, _, _ := am.checkProcessStatus(app)
	if isRunning {
		return fmt.Errorf("app %s is already running", name)
	}

	// 设置日志文件路径
	logFilePath := filepath.Join(app.RunDir, "log", fmt.Sprintf("%s.log", app.Name))

	// 创建日志文件
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	defer logFile.Close()

	// 设置工作目录为指定的运行路径
	cmd := exec.Command(app.Executable, strings.Fields(app.Args)...)
	cmd.Dir = app.RunDir // 指定运行路径
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// 设置进程组ID，使其成为新的进程组长
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// 启动应用程序
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start app: %v", err)
	}

	// 将进程设置为后台运行
	if err := syscall.Setpgid(cmd.Process.Pid, cmd.Process.Pid); err != nil {
		return fmt.Errorf("failed to set process group: %v", err)
	}

	app.Pid = cmd.Process.Pid
	log.Printf("Started %s with PID %d, logging to %s", app.Name, app.Pid, logFilePath)

	am.saveProcessInfo()
	return nil
}

// StopApp 停止指定的应用程序
func (am *AppManager) StopApp(ctx context.Context, name string, force bool) error {
	log := wlog.Common("stop_app")
	am.mu.Lock()
	defer am.mu.Unlock()
	app, ok := am.Apps[name]
	if !ok {
		return fmt.Errorf("app %s not found", name)
	}

	isRunning, pid, isManagedByKenv := am.checkProcessStatus(app)
	if !isRunning {
		return fmt.Errorf("app %s is not running", name)
	}

	if !isManagedByKenv && !force {
		return fmt.Errorf("app %s is running but not managed by kenv. Use -f to force stop", name)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	err = process.Kill()
	if err != nil {
		return err
	}

	app.Pid = 0
	log.Printf("Stopped %s", app.Name)

	am.saveProcessInfo()
	return nil
}

// RestartApp 重启指定的应用程序
func (am *AppManager) RestartApp(ctx context.Context, name string, force bool) error {

	err := am.StopApp(ctx, name, force)
	if err != nil && !strings.Contains(err.Error(), "is not running") {
		return err
	}
	return am.StartApp(ctx, name)
}

// MonitorApps 监控所有应用程序并保持它们运行
func (am *AppManager) MonitorApps(ctx context.Context) {
	log := wlog.Common("monitor_apps")
	for {
		am.mu.Lock()
		for _, app := range am.Apps {
			if app.Pid != 0 {
				process, err := os.FindProcess(app.Pid)
				if err != nil || process.Signal(syscall.Signal(0)) != nil {
					log.Printf("Restarting %s", app.Name)
					err := am.StartApp(ctx, app.Name)
					if err != nil {
						log.Printf("Error restarting %s: %v", app.Name, err)
					}
				}
			}
		}
		am.mu.Unlock()
		time.Sleep(30 * time.Second)
	}
}

// TailLog 查看指定应用程序的日志
func (am *AppManager) TailLog(ctx context.Context, name string) error {
	log, ctx := wlog.FromHold(ctx, "tail_log")
	log.Tracef("Enter tail log for %s", name)
	am.mu.Lock()
	defer am.mu.Unlock()
	// 确定日志文件路径
	logFile := am.pathToDetectedLogFile(ctx, name)
	if logFile == "" {
		return fmt.Errorf("failed to determine log file path for %s", name)
	}

	cmd := exec.Command("tail", "-f", "-n", "1000", logFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// StatApp 提供指定应用程序的详细状态信息
func (am *AppManager) StatApp(ctx context.Context, name string, multipleApps bool) error {

	am.mu.Lock()
	defer am.mu.Unlock()
	app, ok := am.Apps[name]
	if !ok {
		return fmt.Errorf("app %s not found", name)
	}

	isRunning, pid, isManagedByKenv := am.checkProcessStatus(app)
	ports, _ := GetListeningPorts(runtime.GOOS)
	appPorts := ports[strconv.Itoa(pid)]
	nginxConfig, _ := GetNginxConfig(runtime.GOOS, app.Name)
	procInfo, _ := GetProcessInfo(runtime.GOOS, pid)

	am.printer.PrintAppStatus(app, isRunning, pid, isManagedByKenv, appPorts, nginxConfig, procInfo, multipleApps)

	return nil
}

type ExternalPort struct {
	Port       string
	Protocol   string
	ServerName string
}

func parseNginxConfig(config string) []ExternalPort {

	var externalPorts []ExternalPort
	lines := strings.Split(config, "\n")
	var currentPort ExternalPort

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "listen") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				currentPort.Port = parts[1]
				if strings.Contains(line, "ssl") {
					currentPort.Protocol = "https"
				} else {
					currentPort.Protocol = "http"
				}
			}
		} else if strings.HasPrefix(line, "server_name") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				currentPort.ServerName = parts[1]
				externalPorts = append(externalPorts, currentPort)
				currentPort = ExternalPort{}
			}
		}
	}

	return externalPorts
}

// 新增方法：保存进程信息到文件
func (am *AppManager) saveProcessInfo() error {

	data := make(map[string]ProcessInfo)
	for name, app := range am.Apps {
		if app.Pid != 0 {
			data[name] = ProcessInfo{
				Pid:       app.Pid,
				StartTime: time.Now().Unix(),
			}
		}
	}

	file, err := os.Create("process_info.json")
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(data)
}

// 新增方法：从文件加载进程信息
func (am *AppManager) loadProcessInfo() error {
	log := wlog.Common("load_process_info")
	log.Tracef("正在加载进程信息缓存文件\n")
	file, err := os.Open("process_info.json")
	if err != nil {
		if os.IsNotExist(err) {
			log.Tracef("缓存文件不存在，跳过加载\n")
			return nil // 文件不存在，不是错误
		}
		return err
	}
	defer file.Close()

	var data map[string]ProcessInfo
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return err
	}

	for name, info := range data {
		if app, ok := am.Apps[name]; ok {
			log.Tracef("从缓存加载应用 %s 的 PID: %d\n", name, info.Pid)
			app.Pid = info.Pid
		}
	}

	return nil
}

// 新增批量操作方法
func (am *AppManager) BatchStartApps(ctx context.Context, patterns []string) error {
	log, ctx := wlog.FromHold(ctx, "batch_start_apps")
	names := am.matchAppNames(patterns)
	if len(names) == 0 {
		// 提示支持的应用程序
		supportedApps := am.GetAllAppNames(ctx)
		return fmt.Errorf("no matching apps found. Supported apps: %v", supportedApps)
	}
	for _, name := range names {
		err := am.StartApp(ctx, name)
		if err != nil {
			log.Printf("Error starting %s: %v", name, err)
		}
	}
	return nil
}

func (am *AppManager) BatchStopApps(ctx context.Context, patterns []string, force bool) error {
	log := wlog.Common("batch_stop_apps")
	names := am.matchAppNames(patterns)
	for _, name := range names {
		err := am.StopApp(ctx, name, force)
		if err != nil {
			log.Printf("Error stopping %s: %v", name, err)
		}
	}
	return nil
}

func (am *AppManager) BatchRestartApps(ctx context.Context, patterns []string, force bool) error {
	log := wlog.Common("batch_restart_apps")
	names := am.matchAppNames(patterns)
	for _, name := range names {
		err := am.RestartApp(ctx, name, force)
		if err != nil {
			log.Printf("Error restarting %s: %v", name, err)
		}
	}
	return nil
}

// 新增方法：匹配应用名称
func (am *AppManager) matchAppNames(patterns []string) []string {
	var matchedNames []string
	for _, pattern := range patterns {
		for name := range am.Apps {
			matched, _ := filepath.Match(pattern, name)
			if matched {
				matchedNames = append(matchedNames, name)
			}
		}
	}
	return uniqueStrings(matchedNames)
}

// 新增方法：批量获取应用状态
func (am *AppManager) BatchStatApps(ctx context.Context, patterns []string) error {
	log, ctx := wlog.FromHold(ctx, "batch_stat_apps")
	log.Tracef("Enter batch stat apps")
	names := am.matchAppNames(patterns)
	for i, name := range names {
		if i > 0 {
			fmt.Println("---")
		}
		err := am.StatApp(ctx, name, len(names) > 1)
		if err != nil {
			log.Printf("Error getting status for %s: %v", name, err)
		}
	}
	return nil
}

func main() {
	manager := NewAppManager()

	app := &cli.App{
		Name:  "kenv",
		Usage: "Manage applications",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Show verbose output",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List all applications",
				Action: func(c *cli.Context) error {
					manager.ListApps()
					return nil
				},
			},
			{
				Name:  "start",
				Usage: "Start one or more applications (supports wildcards)",
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						names := manager.GetAllAppNames(c.Context)
						return fmt.Errorf("at least one app name or pattern is required. \n---\nSupported apps: \n%v", strings.Join(names, "\n"))
					}
					return manager.BatchStartApps(c.Context, c.Args().Slice())
				},
			},
			{
				Name:  "stop",
				Usage: "Stop one or more applications (supports wildcards)",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Force stop the applications even if they're not managed by kenv",
					},
				},
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						return fmt.Errorf("at least one app name or pattern is required")
					}
					return manager.BatchStopApps(c.Context, c.Args().Slice(), c.Bool("force"))
				},
			},
			{
				Name:  "restart",
				Usage: "Restart one or more applications (supports wildcards)",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Force restart the applications even if they're not managed by kenv",
					},
				},
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						return fmt.Errorf("at least one app name or pattern is required")
					}
					return manager.BatchRestartApps(c.Context, c.Args().Slice(), c.Bool("force"))
				},
			},
			{
				Name:  "log",
				Usage: "Tail the log of an application",
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						return fmt.Errorf("app name is required")
					}
					return manager.TailLog(c.Context, c.Args().First())
				},
			},
			{
				Name:  "stat",
				Usage: "Show detailed status of one or more applications (supports wildcards)",
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						return fmt.Errorf("at least one app name or pattern is required")
					}
					return manager.BatchStatApps(c.Context, c.Args().Slice())
				},
			},
		},
		Before: func(c *cli.Context) error {
			SetVerbose(c.Bool("verbose"))
			wlog.DefaultWLog.SetLevel(logrus.TraceLevel)

			manager.printer.PrintVerbose("详细模式已启用\n")
			if err := manager.LoadConfig(c.Context, ConfFile); err != nil {
				return err
			}
			return manager.loadProcessInfo()
		},
		After: func(c *cli.Context) error {
			return manager.saveProcessInfo()
		},
		Action: func(c *cli.Context) error {
			cli.ShowAppHelp(c)
			manager.printer.PrintInfo("\nCurrent application status:")
			manager.ListApps()
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		manager.printer.PrintError("Fatal error: %v", err)
		os.Exit(1)
	}
}
