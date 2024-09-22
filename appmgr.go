package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/khicago/irr"
	"github.com/khicago/wlog"
	"gopkg.in/yaml.v2"
)

// AppConfig 结构体用于表示配置文件中的应用程序信息
type AppConfig struct {
	Name        string `yaml:"name"`
	Executable  string `yaml:"executable"`
	Args        string `yaml:"args"`
	RunDir      string `yaml:"run_dir"`
	LogFilePath string `yaml:"log_file_path"`
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
	Name        string
	Executable  string
	Args        string
	Pid         int
	RunDir      string
	LogFilePath string
}

// AppManager 结构体用于管理所有应用程序
type AppManager struct {
	Apps    map[string]*App
	mu      sync.Mutex
	printer *Printer
}

const ConfFile = "kenv.conf.yml"

// NewAppManager 创建一个新的 AppManager 实例
func NewAppManager() *AppManager {
	return &AppManager{
		Apps:    make(map[string]*App),
		printer: NewPrinter(),
	}
}

// LoadConfig 从配置文件加载应用程序信息
func (am *AppManager) LoadConfig(ctx context.Context, configFile string) error {
	log, ctx := wlog.By(ctx, "LoadConfig").Field("configFile", configFile).Branch()
	log.Tracef("从配置文件加载应用程序信息")
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Errorf("读取配置文件失败: %v", err)
		return irr.Error("error reading config file: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Errorf("解析配置文件失败: %v", err)
		return irr.Error("error parsing config file: %v", err)
	}

	for _, appConfig := range config.Apps {
		am.AddApp(ctx, appConfig)
	}

	return nil
}

// AddApp 添加一个新的应用程序到管理器
func (am *AppManager) AddApp(ctx context.Context, appConfig AppConfig) {
	log := wlog.By(ctx, "AddApp").Field("appName", appConfig.Name).Leaf()
	log.Tracef("添加一个新的应用程序到管理器")
	am.mu.Lock()
	defer am.mu.Unlock()

	am.Apps[appConfig.Name] = &App{
		Name:        appConfig.Name,
		Executable:  appConfig.Executable,
		Args:        appConfig.Args,
		RunDir:      appConfig.RunDir,
		LogFilePath: appConfig.LogFilePath,
	}
}

// SaveProcessInfo 保存进程信息到文件
func (am *AppManager) SaveProcessInfo(ctx context.Context) error {
	log := wlog.By(ctx, "SaveProcessInfo").Leaf()
	log.Tracef("保存进程信息到文件")
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
		log.Errorf("创建进程信息文件失败: %v", err)
		return irr.Wrap(err, "error creating process info file")
	}
	defer file.Close()

	err = json.NewEncoder(file).Encode(data)
	if err != nil {
		log.Errorf("写入进程信息文件失败: %v", err)
		return irr.Wrap(err, "error writing process info file")
	}

	return nil
}

// LoadProcessInfo 从文件加载进程信息
func (am *AppManager) LoadProcessInfo(ctx context.Context) error {
	log := wlog.Leaf(ctx, "LoadProcessInfo")
	log.Tracef("正在加载进程信息缓存文件")
	file, err := os.Open("process_info.json")
	if err != nil {
		if os.IsNotExist(err) {
			log.Tracef("缓存文件不存在，跳过加载")
			return nil // 文件不存在，不是错误
		}
		return irr.Wrap(err, "error opening process info file")
	}
	defer file.Close()

	var data map[string]ProcessInfo
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return irr.Wrap(err, "error decoding process info file")
	}

	for name, info := range data {
		if app, ok := am.Apps[name]; ok {
			log.Tracef("从缓存加载应用 %s 的 PID: %d", name, info.Pid)
			app.Pid = info.Pid
		}
	}

	return nil
}

// GetAllAppNames 获取所有应用程序名称
func (am *AppManager) GetAllAppNames(ctx context.Context) []string {
	log := wlog.Leaf(ctx, "GetAllAppNames")
	log.Tracef("获取所有应用程序名称")
	am.mu.Lock()
	defer am.mu.Unlock()
	names := make([]string, 0, len(am.Apps))
	for name := range am.Apps {
		names = append(names, name)
	}
	return names
}

// MatchAppNames 匹配应用名称
func (am *AppManager) MatchAppNames(ctx context.Context, patterns []string) []string {
	log := wlog.By(ctx, "MatchAppNames").Field("patterns", patterns).Leaf()
	log.Tracef("匹配应用名称")
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

// pathToDetectedLogFile 确定日志文件路径
func (am *AppManager) pathToDetectedLogFile(ctx context.Context, appName string) (logFile string) {
	log := wlog.By(ctx, "pathToDetectedLogFile").Field("appName", appName).Leaf()
	log.Tracef("确定日志文件路径")
	// 不加锁，外部调用者加锁
	app, ok := am.Apps[appName]
	if !ok {
		return ""
	}

	// 确定日志文件路径
	if app.LogFilePath != "" {
		// 优先使用配置中的日志文件路径
		if filepath.IsAbs(app.LogFilePath) {
			logFile = app.LogFilePath // 绝对路径
		} else {
			if app.RunDir != "" {
				logFile = filepath.Join(app.RunDir, app.LogFilePath) // 相对路径 + runDir
			} else {
				logFile = app.LogFilePath // 直接使用相对路径
			}
		}
	} else {
		// 没有配置 logFile，兜底到 runDir + ./logs
		if app.RunDir != "" {
			logFile = filepath.Join(app.RunDir, "log") // runDir + ./log
		} else {
			logFile = "./log" // 直接 ./log
		}
	}
	return logFile
}

// uniqueStrings 辅助函数：去重字符串切片
func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
