package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
)

// AppConfig 结构体用于表示配置文件中的应用程序信息
type AppConfig struct {
	Name    string `yaml:"name"`
	Command string `yaml:"command"`
}

// Config 结构体用于表示整个配置文件
type Config struct {
	Apps []AppConfig `yaml:"apps"`
}

// ProcessInfo 结构体用于存储进程信息
type ProcessInfo struct {
	Pid       int   `json:"pid"`
	StartTime int64 `json:"start_time"`
}

// App 结构体用于表示一个应用程序
type App struct {
	Name    string
	Command string
	Pid     int
}

// AppManager 结构体用于管理所有应用程序
type AppManager struct {
	Apps map[string]*App
	mu   sync.Mutex
}

// SystemCommands 结构体用于存储不同操作系统的系统命令
type SystemCommands struct {
	GetPort      []string
	GetNginxConf []string
	GetProcInfo  []string
}

const ConfFile = "kenv.conf.yml"

var sysCommands = map[string]SystemCommands{
	"linux": {
		GetPort:      []string{"ss", "-tlnp"},
		GetNginxConf: []string{"grep", "-R", "--include=*.conf"},
		GetProcInfo:  []string{"ps", "-p", "%d", "-o", "pid,ppid,user,%cpu,%mem,etime,cmd"},
	},
	"darwin": {
		GetPort:      []string{"lsof", "-i", "-P", "-n"},
		GetNginxConf: []string{"grep", "-R", "--include=*.conf"},
		GetProcInfo:  []string{"ps", "-p", "%d", "-o", "pid,ppid,user,%cpu,%mem,etime,command"},
	},
	"windows": {
		GetPort:      []string{"netstat", "-ano"},
		GetNginxConf: []string{"findstr", "/s", "/i"},
		GetProcInfo:  []string{"tasklist", "/FI", "PID eq %d", "/V", "/FO", "LIST"},
	},
}

// NewAppManager 创建一个新的 AppManager 实例
func NewAppManager() *AppManager {
	return &AppManager{
		Apps: make(map[string]*App),
	}
}

// LoadConfig 从配置文件加载应用程序信息
func (am *AppManager) LoadConfig(configFile string) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("error parsing config file: %v", err)
	}

	for _, appConfig := range config.Apps {
		am.AddApp(appConfig)
	}

	return nil
}

// AddApp 添加一个新的应用程序到管理器
func (am *AppManager) AddApp(appConfig AppConfig) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.Apps[appConfig.Name] = &App{
		Name:    appConfig.Name,
		Command: appConfig.Command,
	}
}

// ListApps 列出所有正在运行的应用程序
func (am *AppManager) ListApps() {
	am.mu.Lock()
	defer am.mu.Unlock()
	for _, app := range am.Apps {
		isRunning, pid, isManagedByKenv := am.checkProcessStatus(app)
		if isRunning {
			if isManagedByKenv {
				fmt.Printf("%s is running with PID %d (managed by kenv)\n", app.Name, pid)
			} else {
				fmt.Printf("%s is running with PID %d (not managed by kenv)\n", app.Name, pid)
			}
		} else {
			fmt.Printf("%s is not running\n", app.Name)
		}
	}
}

// 新增方法：检查进程状态
func (am *AppManager) checkProcessStatus(app *App) (isRunning bool, pid int, isManagedByKenv bool) {
	if app.Pid != 0 {
		process, err := os.FindProcess(app.Pid)
		if err == nil && process.Signal(syscall.Signal(0)) == nil {
			return true, app.Pid, true
		}
	}

	pid, err := findProcessByName(app.Name, app.Command)
	if err == nil && pid != 0 {
		return true, pid, false
	}

	return false, 0, false
}

// StartApp 启动指定的应用程序
func (am *AppManager) StartApp(name string) error {
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

	cmd := exec.Command("sh", "-c", app.Command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		return err
	}

	app.Pid = cmd.Process.Pid
	log.Printf("Started %s with PID %d", app.Name, app.Pid)

	am.saveProcessInfo()
	return nil
}

// StopApp 停止指定的应用程序
func (am *AppManager) StopApp(name string, force bool) error {
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
func (am *AppManager) RestartApp(name string, force bool) error {
	err := am.StopApp(name, force)
	if err != nil && !strings.Contains(err.Error(), "is not running") {
		return err
	}
	return am.StartApp(name)
}

// MonitorApps 监控所有应用程序并保持它们运行
func (am *AppManager) MonitorApps() {
	for {
		am.mu.Lock()
		for _, app := range am.Apps {
			if app.Pid != 0 {
				process, err := os.FindProcess(app.Pid)
				if err != nil || process.Signal(syscall.Signal(0)) != nil {
					log.Printf("Restarting %s", app.Name)
					err := am.StartApp(app.Name)
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
func (am *AppManager) TailLog(name string) error {
	logFile := filepath.Join("logs", name+".log")
	cmd := exec.Command("tail", "-f", "-n", "1000", logFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// StatApp 提供指定应用程序的详细状态信息
func (am *AppManager) StatApp(name string) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	app, ok := am.Apps[name]
	if !ok {
		return fmt.Errorf("app %s not found", name)
	}

	var processInfo strings.Builder
	var criticalInfo strings.Builder

	fmt.Fprintf(&processInfo, "应用程序: %s\n", app.Name)
	fmt.Fprintf(&processInfo, "命令: %s\n", app.Command)

	isRunning, pid, isManagedByKenv := am.checkProcessStatus(app)
	if isRunning {
		fmt.Fprintf(&criticalInfo, "状态: 运行中\n")
		fmt.Fprintf(&criticalInfo, "PID: %d\n", pid)
		if isManagedByKenv {
			fmt.Fprintf(&criticalInfo, "管理者: kenv\n")
		} else {
			fmt.Fprintf(&criticalInfo, "管理者: 外部进程\n")
		}

		ports, err := getListeningPorts()
		if err != nil {
			fmt.Fprintf(&processInfo, "获取监听端口时出错: %v\n", err)
		} else {
			if appPorts, ok := ports[strconv.Itoa(pid)]; ok {
				fmt.Fprintf(&criticalInfo, "内部监听端口: %s\n", strings.Join(appPorts, ", "))
			} else {
				fmt.Fprintf(&processInfo, "未找到 PID %d 的监听端口\n", pid)
			}
		}

		nginxConfig, err := getNginxConfig(app.Name)
		if err != nil {
			fmt.Fprintf(&processInfo, "无法获取 Nginx 配置 (错误: %v)\n", err)
		} else {
			externalPorts := parseNginxConfig(nginxConfig)
			if len(externalPorts) > 0 {
				fmt.Fprintf(&criticalInfo, "外部监听端口:\n")
				for _, ep := range externalPorts {
					fmt.Fprintf(&criticalInfo, "  - %s (%s) -> %s\n", ep.Port, ep.Protocol, ep.ServerName)
				}
			} else {
				fmt.Fprintf(&processInfo, "未找到外部监听端口\n")
			}
			fmt.Fprintf(&processInfo, "Nginx 配置:\n%s\n", nginxConfig)
		}

		procInfo, err := getProcessInfo(pid)
		if err != nil {
			fmt.Fprintf(&processInfo, "无法获取进程详情 (错误: %v)\n", err)
		} else {
			fmt.Fprintf(&processInfo, "进程详情:\n%s", procInfo)
		}
	} else {
		fmt.Fprintf(&criticalInfo, "状态: 未运行\n")
	}

	// 打印非关键信息
	fmt.Print(processInfo.String())

	// 打印一个分隔线
	fmt.Println("\n--- 关键信息 ---")

	// 打印关键信息
	fmt.Print(criticalInfo.String())

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

func getNginxConfig(appName string) (string, error) {
	nginxPaths := []string{"/etc/nginx/sites-enabled/", "/etc/nginx/conf.d/", "/usr/local/nginx/conf/"}
	var configs []string

	os := runtime.GOOS
	for _, path := range nginxPaths {
		cmd := exec.Command(sysCommands[os].GetNginxConf[0], sysCommands[os].GetNginxConf[1:]...)
		cmd.Args = append(cmd.Args, appName, path)
		output, err := cmd.Output()
		if err == nil && len(output) > 0 {
			configs = append(configs, string(output))
		}
	}

	if len(configs) == 0 {
		return "", fmt.Errorf("no Nginx configuration found for %s", appName)
	}

	return strings.Join(configs, "\n"), nil
}

func getListeningPorts() (map[string][]string, error) {
	os := runtime.GOOS
	switch os {
	case "linux":
		return getLinuxPorts()
	case "darwin":
		return getDarwinPorts()
	case "windows":
		return getWindowsPorts()
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", os)
	}
}

func getLinuxPorts() (map[string][]string, error) {
	cmd := exec.Command(sysCommands["linux"].GetPort[0], sysCommands["linux"].GetPort[1:]...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running port detection command: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	ports := make(map[string][]string)

	for _, line := range lines {
		if !strings.HasPrefix(line, "LISTEN") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		localAddress := fields[3]
		process := fields[len(fields)-1]

		pid, port := extractPidAndPort(process, localAddress)
		if pid != "" && port != "" {
			ports[pid] = append(ports[pid], port)
		}
	}

	return ports, nil
}

func getDarwinPorts() (map[string][]string, error) {
	cmd := exec.Command(sysCommands["darwin"].GetPort[0], sysCommands["darwin"].GetPort[1:]...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running port detection command: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	ports := make(map[string][]string)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		pid := fields[1]
		localAddress := fields[8]

		_, port := extractPidAndPort(pid, localAddress)
		if port != "" {
			ports[pid] = append(ports[pid], port)
		}
	}

	return ports, nil
}

func getWindowsPorts() (map[string][]string, error) {
	cmd := exec.Command(sysCommands["windows"].GetPort[0], sysCommands["windows"].GetPort[1:]...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running port detection command: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	ports := make(map[string][]string)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		localAddress := fields[1]
		pid := fields[4]

		_, port := extractPidAndPort(pid, localAddress)
		if port != "" {
			ports[pid] = append(ports[pid], port)
		}
	}

	return ports, nil
}

func extractPidAndPort(process, localAddress string) (string, string) {
	pidStart := strings.Index(process, "pid=")
	var pid string
	if pidStart != -1 {
		pidEnd := strings.Index(process[pidStart:], ",")
		if pidEnd == -1 {
			pidEnd = len(process) - pidStart
		} else {
			pidEnd += pidStart
		}
		pid = process[pidStart+4 : pidEnd]
	} else {
		pid = process
	}

	var port string
	if strings.HasPrefix(localAddress, "[") {
		parts := strings.Split(localAddress, "]:")
		if len(parts) == 2 {
			port = parts[1]
		}
	} else {
		parts := strings.Split(localAddress, ":")
		if len(parts) == 2 {
			port = parts[1]
		}
	}

	if port == "*" {
		port = ""
	}

	return pid, port
}

func getProcessInfo(pid int) (string, error) {
	os := runtime.GOOS
	cmd := exec.Command(sysCommands[os].GetProcInfo[0], sysCommands[os].GetProcInfo[1:]...)
	cmd.Args[2] = fmt.Sprintf(cmd.Args[2], pid)

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// 新增函数：通过进程名查找PID
func findProcessByName(name string, command string) (int, error) {
	// 首先尝试使用完整的命令行
	cmd := exec.Command("pgrep", "-f", command)
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		return parsePID(output)
	}

	// 如果失败，尝试使用命令中的可执行文件名
	parts := strings.Fields(command)
	if len(parts) > 0 {
		execName := filepath.Base(parts[0])
		cmd = exec.Command("pgrep", "-f", execName)
		output, err = cmd.Output()
		if err == nil && len(output) > 0 {
			return parsePID(output)
		}
	}

	// 最后，尝试使用配置中的名称
	cmd = exec.Command("pgrep", "-f", name)
	output, err = cmd.Output()
	if err == nil && len(output) > 0 {
		return parsePID(output)
	}

	return 0, fmt.Errorf("process not found")
}

func parsePID(output []byte) (int, error) {
	pids := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(pids) > 0 {
		return strconv.Atoi(pids[0])
	}
	return 0, fmt.Errorf("no valid PID found")
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
	file, err := os.Open("process_info.json")
	if err != nil {
		if os.IsNotExist(err) {
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
			app.Pid = info.Pid
		}
	}

	return nil
}

func main() {
	manager := NewAppManager()

	app := &cli.App{
		Name:  "app_manager",
		Usage: "Manage applications",
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
				Usage: "Start an application",
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						return fmt.Errorf("app name is required")
					}
					return manager.StartApp(c.Args().First())
				},
			},
			{
				Name:  "stop",
				Usage: "Stop an application",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Force stop the application even if it's not managed by kenv",
					},
				},
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						return fmt.Errorf("app name is required")
					}
					return manager.StopApp(c.Args().First(), c.Bool("force"))
				},
			},
			{
				Name:  "restart",
				Usage: "Restart an application",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Force restart the application even if it's not managed by kenv",
					},
				},
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						return fmt.Errorf("app name is required")
					}
					return manager.RestartApp(c.Args().First(), c.Bool("force"))
				},
			},
			{
				Name:  "log",
				Usage: "Tail the log of an application",
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						return fmt.Errorf("app name is required")
					}
					return manager.TailLog(c.Args().First())
				},
			},
			{
				Name:  "stat",
				Usage: "Show detailed status of an application",
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						return fmt.Errorf("app name is required")
					}
					return manager.StatApp(c.Args().First())
				},
			},
		},
		Before: func(c *cli.Context) error {
			if err := manager.LoadConfig(ConfFile); err != nil {
				return err
			}
			return manager.loadProcessInfo()
		},
		After: func(c *cli.Context) error {
			return manager.saveProcessInfo()
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
