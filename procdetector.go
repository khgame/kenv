package main

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/khicago/wlog"
)

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
func FindProcessByName(ctx context.Context, name, executable, args string) (int, error) {
	log := wlog.By(ctx, "FindProcessByName").Fields(wlog.Fields{"name": name, "executable": executable, "args": args}).Leaf()

	cmd := exec.Command("ps", "-eo", "pid,comm,args")

	log.Tracef("执行命令: %s %s", cmd.Path, strings.Join(cmd.Args, " "))
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("error running ps command: %v", err)
	}

	log.Tracef("ps 命令原始输出:\n%s", string(output))

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

		log.Tracef("检查进程 PID %d: %s %s", pid, comm, processArgs)

		// 排除内核线程
		if strings.HasPrefix(comm, "[") && strings.HasSuffix(comm, "]") {
			continue
		}

		// 检查可执行文件名是否精确匹配
		if comm == executable || strings.HasSuffix(processArgs, executable) {
			if pid > 100 && !isSystemProcess(processArgs) {
				log.Tracef("找到匹配的进程 PID %d", pid)
				return pid, nil
			}
		}
	}

	log.Tracef("未找到匹配的进程")
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
func GetListeningPorts(ctx context.Context, os string) (map[string][]string, error) {
	log := wlog.By(ctx, "GetListeningPorts").Field("os", os).Leaf()
	switch os {
	case "linux":
		return getLinuxPorts(ctx)
	case "darwin":
		return getDarwinPorts(ctx)
	case "windows":
		return getWindowsPorts(ctx)
	default:
		log.Errorf("不支持的操作系统: %s", os)
		return nil, fmt.Errorf("unsupported operating system: %s", os)
	}
}

func getLinuxPorts(ctx context.Context) (map[string][]string, error) {
	log := wlog.By(ctx, "getLinuxPorts").Leaf()
	cmd := exec.Command(detectors["linux"].GetPort[0], detectors["linux"].GetPort[1:]...)
	log.Tracef("执行命令: %s %s", cmd.Path, strings.Join(cmd.Args, " "))
	output, err := cmd.Output()
	if err != nil {
		log.Errorf("执行端口检测命令失败: %v", err)
		return nil, fmt.Errorf("error running port detection command: %v", err)
	}

	log.Tracef("ss 命令原始输出:\n%s", string(output))

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
			log.Tracef("找到端口 %s 对应的 PID %s", port, pid)
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

func getDarwinPorts(ctx context.Context) (map[string][]string, error) {
	log := wlog.By(ctx, "getDarwinPorts").Leaf()
	cmd := exec.Command(detectors["darwin"].GetPort[0], detectors["darwin"].GetPort[1:]...)
	log.Tracef("执行命令: %s %s", cmd.Path, strings.Join(cmd.Args, " "))
	output, err := cmd.Output()
	if err != nil {
		log.Errorf("执行端口检测命令失败: %v", err)
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
			log.Tracef("找到端口 %s 对应的 PID %s", port, pid)
		}
	}

	return ports, nil
}

func getWindowsPorts(ctx context.Context) (map[string][]string, error) {
	log := wlog.By(ctx, "getWindowsPorts").Leaf()
	cmd := exec.Command(detectors["windows"].GetPort[0], detectors["windows"].GetPort[1:]...)
	log.Tracef("执行命令: %s %s", cmd.Path, strings.Join(cmd.Args, " "))
	output, err := cmd.Output()
	if err != nil {
		log.Errorf("执行端口检测命令失败: %v", err)
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
			log.Tracef("找到端口 %s 对应的 PID %s", port, pid)
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
func GetProcessInfo(ctx context.Context, os string, pid int) (string, error) {
	log := wlog.By(ctx, "GetProcessInfo").Fields(wlog.Fields{"os": os, "pid": pid}).Leaf()
	cmd := exec.Command(detectors[os].GetProcInfo[0], detectors[os].GetProcInfo[1:]...)
	cmd.Args[2] = fmt.Sprintf(cmd.Args[2], pid)

	log.Tracef("执行命令: %s %s", cmd.Path, strings.Join(cmd.Args, " "))
	output, err := cmd.Output()
	if err != nil {
		log.Errorf("获取进程信息失败: %v", err)
		return "", err
	}
	return string(output), nil
}

// GetNginxConfig 获取 Nginx 配置
func GetNginxConfig(ctx context.Context, os, appName string) (string, error) {
	log := wlog.By(ctx, "GetNginxConfig").Fields(wlog.Fields{"os": os, "appName": appName}).Leaf()
	nginxPaths := []string{"/etc/nginx/sites-enabled/", "/etc/nginx/conf.d/", "/usr/local/nginx/conf/"}
	var configs []string

	for _, path := range nginxPaths {
		cmd := exec.Command(detectors[os].GetNginxConf[0], detectors[os].GetNginxConf[1:]...)
		cmd.Args = append(cmd.Args, appName, path)
		log.Tracef("执行命令: %s %s", cmd.Path, strings.Join(cmd.Args, " "))
		output, err := cmd.Output()
		if err == nil && len(output) > 0 {
			configs = append(configs, string(output))
		}
	}

	if len(configs) == 0 {
		log.Errorf("未找到 %s 的 Nginx 配置", appName)
		return "", fmt.Errorf("no Nginx configuration found for %s", appName)
	}

	return strings.Join(configs, "\n"), nil
}
