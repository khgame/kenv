package main

import (
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/khicago/wlog"
	"github.com/sirupsen/logrus"
)

type ColoredFormatter struct {
	logrus.TextFormatter
}

func (f *ColoredFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// 获取原始格式化的日志
	b, err := f.TextFormatter.Format(entry)
	if err != nil {
		return nil, err
	}

	// 根据日志级别设置不同的颜色
	var levelColor *color.Color
	var lineColor *color.Color
	switch entry.Level {
	case logrus.TraceLevel, logrus.DebugLevel:
		levelColor = color.New(color.FgCyan)
		lineColor = color.New(color.FgHiBlack) // 灰色
	case logrus.InfoLevel:
		levelColor = color.New(color.FgGreen)
	case logrus.WarnLevel:
		levelColor = color.New(color.FgYellow)
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		levelColor = color.New(color.FgRed)
	default:
		levelColor = color.New(color.FgWhite)
	}

	// 将日志级别文本替换为彩色文本
	coloredLevel := levelColor.Sprint(strings.ToUpper(entry.Level.String()))
	logLine := strings.Replace(string(b), strings.ToUpper(entry.Level.String()), coloredLevel, 1)

	// 如果是 TRACE 级别，将整行变为灰色
	if entry.Level == logrus.TraceLevel || entry.Level == logrus.DebugLevel {
		logLine = lineColor.Sprint(logLine)
	}

	// 强调 wlog.fp 后的 chain
	emphasisColor := color.New(color.FgHiYellow).SprintFunc() // 高亮黄色
	logLine = strings.Replace(logLine, wlog.KeyFingerPrint+"=", wlog.KeyFingerPrint+"="+emphasisColor(""), -1)

	return []byte(logLine), nil
}

func initLogger() *logrus.Logger {
	logger := logrus.New()
	logger.Formatter = &ColoredFormatter{
		TextFormatter: logrus.TextFormatter{
			ForceColors:               true,
			DisableColors:             false,
			FullTimestamp:             true,
			TimestampFormat:           "2006-01-02 15:04:05",
			DisableLevelTruncation:    true,
			PadLevelText:              true,
			QuoteEmptyFields:          true,
			EnvironmentOverrideColors: true,
		},
	}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.InfoLevel)

	return logger
}
