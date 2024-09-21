package main

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

var verbose bool

// SetVerbose 设置详细日志模式
func SetVerbose(v bool) {
	verbose = v
}

// logVerbose 打印详细日志
func logVerbose(format string, v ...interface{}) {
	if !verbose {
		return
	}
	gray := color.New(color.FgHiBlack).SprintfFunc()
	log.Printf(gray(format), v...)
}

// ProcessDetector 结构体用于存储不同操作系统的系统命令
type ProcessDetector struct {
	GetPort      []string
	GetNginxConf []string
	GetProcInfo  []string
}

var detectors = map[string]ProcessDetector{
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

// FindProcessByName 通过进程名查找PID
func FindProcessByName(name, executable, args string) (int, error) {
	cmd := exec.Command("ps", "-eo", "pid,comm,args")
	logVerbose("执行命令: %s %s\n", cmd.Path, strings.Join(cmd.Args, " "))
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("error running ps command: %v", err)
	}

	logVerbose("ps 命令原始输出:\n%s\n", string(output))

	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] { // 跳过标题行
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		comm := fields[1]
		processArgs := strings.Join(fields[2:], " ")

		logVerbose("检查进程 PID %d: %s %s\n", pid, comm, processArgs)

		// 排除内核线程
		if strings.HasPrefix(comm, "[") && strings.HasSuffix(comm, "]") {
			continue
		}

		// 检查可执行文件名是否精确匹配
		if comm == executable || strings.HasSuffix(processArgs, executable) {
			if pid > 100 && !isSystemProcess(processArgs) {
				logVerbose("找到匹配的进程 PID %d\n", pid)
				return pid, nil
			}
		}
	}

	logVerbose("未找到匹配的进程\n")
	return 0, fmt.Errorf("process not found")
}

func isSystemProcess(command string) bool {
	systemProcesses := []string{"/sbin/", "/usr/sbin/", "systemd", "init"}
	for _, sp := range systemProcesses {
		if strings.HasPrefix(command, sp) {
			return true
		}
	}
	return false
}

// GetListeningPorts 获取监听端口
func GetListeningPorts(os string) (map[string][]string, error) {
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
	cmd := exec.Command(detectors["linux"].GetPort[0], detectors["linux"].GetPort[1:]...)
	logVerbose("执行命令: %s %s\n", cmd.Path, strings.Join(cmd.Args, " "))
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running port detection command: %v", err)
	}

	logVerbose("ss 命令原始输出:\n%s\n", string(output))

	ports := make(map[string][]string)

	lines := strings.Split(string(output), "\n")
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

		pid := extractPidFromUsers(process)
		port := extractPortFromAddress(localAddress)
		if pid != "" && port != "" {
			ports[pid] = append(ports[pid], port)
			logVerbose("! 找到端口 %s 对应的 PID %s\n", port, pid)
		}
	}

	return ports, nil
}

func extractPidFromUsers(users string) string {
	start := strings.Index(users, "pid=")
	if start == -1 {
		return ""
	}
	end := strings.Index(users[start:], ",")
	if end == -1 {
		end = len(users) - start
	} else {
		end += start
	}
	return users[start+4 : end]
}

func extractPortFromAddress(address string) string {
	parts := strings.Split(address, ":")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

func getDarwinPorts() (map[string][]string, error) {
	cmd := exec.Command(detectors["darwin"].GetPort[0], detectors["darwin"].GetPort[1:]...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running port detection command: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	ports := make(map[string][]string)

	for _, line := range lines {
		if !strings.Contains(line, "LISTEN") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		pid := fields[1]
		address := fields[8]
		_, port := extractPidAndPort(pid, address)
		if port != "" {
			ports[pid] = append(ports[pid], port)
		}
	}

	return ports, nil
}

func getWindowsPorts() (map[string][]string, error) {
	cmd := exec.Command(detectors["windows"].GetPort[0], detectors["windows"].GetPort[1:]...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running port detection command: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	ports := make(map[string][]string)

	for _, line := range lines {
		if !strings.Contains(line, "LISTENING") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		address := fields[1]
		pid := fields[4]
		_, port := extractPidAndPort(pid, address)
		if port != "" {
			ports[pid] = append(ports[pid], port)
		}
	}

	return ports, nil
}

func extractPidAndPort(process, localAddress string) (string, string) {
	pid := process

	var port string
	if strings.HasPrefix(localAddress, "[") {
		// IPv6 格式
		parts := strings.Split(localAddress, "]:")
		if len(parts) == 2 {
			port = parts[1]
		}
	} else {
		// IPv4 格式
		parts := strings.Split(localAddress, ":")
		if len(parts) == 2 {
			port = parts[1]
		}
	}

	// 移除可能的前导冒号
	port = strings.TrimPrefix(port, ":")

	// 检查端口是否为数字
	if _, err := strconv.Atoi(port); err != nil {
		port = ""
	}

	return pid, port
}

// GetProcessInfo 获取进程信息
func GetProcessInfo(os string, pid int) (string, error) {
	cmd := exec.Command(detectors[os].GetProcInfo[0], detectors[os].GetProcInfo[1:]...)
	cmd.Args[2] = fmt.Sprintf(cmd.Args[2], pid)

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// GetNginxConfig 获取 Nginx 配置
func GetNginxConfig(os, appName string) (string, error) {
	nginxPaths := []string{"/etc/nginx/sites-enabled/", "/etc/nginx/conf.d/", "/usr/local/nginx/conf/"}
	var configs []string

	for _, path := range nginxPaths {
		cmd := exec.Command(detectors[os].GetNginxConf[0], detectors[os].GetNginxConf[1:]...)
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
