package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

// AppConfig 结构体用于表示配置文件中的应用程序信息
type AppConfig struct {
	Name       string `yaml:"name"`
	Executable string `yaml:"executable"`
	Args       string `yaml:"args"`
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
	Name       string
	Executable string
	Args       string
	Pid        int
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
		Name:       appConfig.Name,
		Executable: appConfig.Executable,
		Args:       appConfig.Args,
	}
}

// SaveProcessInfo 保存进程信息到文件
func (am *AppManager) SaveProcessInfo() error {
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

// LoadProcessInfo 从文件加载进程信息
func (am *AppManager) LoadProcessInfo() error {
	am.printer.PrintVerbose("正在加载进程信息缓存文件\n")
	file, err := os.Open("process_info.json")
	if err != nil {
		if os.IsNotExist(err) {
			am.printer.PrintVerbose("缓存文件不存在，跳过加载\n")
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
			am.printer.PrintVerbose("从缓存加载应用 %s 的 PID: %d\n", name, info.Pid)
			app.Pid = info.Pid
		}
	}

	return nil
}

// GetAllAppNames 获取所有应用程序名称
func (am *AppManager) GetAllAppNames() []string {
	am.mu.Lock()
	defer am.mu.Unlock()
	names := make([]string, 0, len(am.Apps))
	for name := range am.Apps {
		names = append(names, name)
	}
	return names
}

// MatchAppNames 匹配应用名称
func (am *AppManager) MatchAppNames(patterns []string) []string {
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
