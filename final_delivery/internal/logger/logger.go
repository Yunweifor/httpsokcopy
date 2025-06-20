package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// LogLevel 定义日志级别
type LogLevel int

const (
	// DEBUG 调试级别
	DEBUG LogLevel = iota
	// INFO 信息级别
	INFO
	// WARN 警告级别
	WARN
	// ERROR 错误级别
	ERROR
	// FATAL 致命错误级别
	FATAL
)

// Logger 日志记录器接口
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, err error, args ...interface{})
	Fatal(msg string, err error, args ...interface{})
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, err error, args ...interface{})
	Fatalf(format string, err error, args ...interface{})
}

// StandardLogger 标准日志记录器实现
type StandardLogger struct {
	level      LogLevel
	debugLog   *log.Logger
	infoLog    *log.Logger
	warnLog    *log.Logger
	errorLog   *log.Logger
	fatalLog   *log.Logger
	logFile    *os.File
}

// NewLogger 创建新的日志记录器
func NewLogger(levelStr string, logPath string) Logger {
	var level LogLevel
	switch levelStr {
	case "debug":
		level = DEBUG
	case "info":
		level = INFO
	case "warn":
		level = WARN
	case "error":
		level = ERROR
	case "fatal":
		level = FATAL
	default:
		level = INFO
	}

	// 确保日志目录存在
	if err := os.MkdirAll(logPath, 0755); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	// 创建日志文件
	now := time.Now().Format("2006-01-02")
	logFilePath := filepath.Join(logPath, fmt.Sprintf("httpsok-%s.log", now))
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	// 同时输出到控制台和文件
	multiWriter := io.MultiWriter(os.Stdout, logFile)

	// 创建不同级别的日志记录器
	debugLog := log.New(multiWriter, "[DEBUG] ", log.Ldate|log.Ltime|log.Lshortfile)
	infoLog := log.New(multiWriter, "[INFO] ", log.Ldate|log.Ltime)
	warnLog := log.New(multiWriter, "[WARN] ", log.Ldate|log.Ltime)
	errorLog := log.New(multiWriter, "[ERROR] ", log.Ldate|log.Ltime|log.Lshortfile)
	fatalLog := log.New(multiWriter, "[FATAL] ", log.Ldate|log.Ltime|log.Lshortfile)

	return &StandardLogger{
		level:      level,
		debugLog:   debugLog,
		infoLog:    infoLog,
		warnLog:    warnLog,
		errorLog:   errorLog,
		fatalLog:   fatalLog,
		logFile:    logFile,
	}
}

// Debug 记录调试级别日志
func (l *StandardLogger) Debug(msg string, args ...interface{}) {
	if l.level <= DEBUG {
		if len(args) > 0 {
			l.debugLog.Printf("%s: %v", msg, args)
		} else {
			l.debugLog.Println(msg)
		}
	}
}

// Info 记录信息级别日志
func (l *StandardLogger) Info(msg string, args ...interface{}) {
	if l.level <= INFO {
		if len(args) > 0 {
			l.infoLog.Printf("%s: %v", msg, args)
		} else {
			l.infoLog.Println(msg)
		}
	}
}

// Warn 记录警告级别日志
func (l *StandardLogger) Warn(msg string, args ...interface{}) {
	if l.level <= WARN {
		if len(args) > 0 {
			l.warnLog.Printf("%s: %v", msg, args)
		} else {
			l.warnLog.Println(msg)
		}
	}
}

// Error 记录错误级别日志
func (l *StandardLogger) Error(msg string, err error, args ...interface{}) {
	if l.level <= ERROR {
		if err != nil {
			if len(args) > 0 {
				l.errorLog.Printf("%s: %v, error: %v", msg, args, err)
			} else {
				l.errorLog.Printf("%s: %v", msg, err)
			}
		} else {
			if len(args) > 0 {
				l.errorLog.Printf("%s: %v", msg, args)
			} else {
				l.errorLog.Println(msg)
			}
		}
	}
}

// Fatal 记录致命错误级别日志
func (l *StandardLogger) Fatal(msg string, err error, args ...interface{}) {
	if l.level <= FATAL {
		if err != nil {
			if len(args) > 0 {
				l.fatalLog.Fatalf("%s: %v, error: %v", msg, args, err)
			} else {
				l.fatalLog.Fatalf("%s: %v", msg, err)
			}
		} else {
			if len(args) > 0 {
				l.fatalLog.Fatalf("%s: %v", msg, args)
			} else {
				l.fatalLog.Fatal(msg)
			}
		}
	}
}

// Debugf 使用格式化字符串记录调试级别日志
func (l *StandardLogger) Debugf(format string, args ...interface{}) {
	if l.level <= DEBUG {
		l.debugLog.Printf(format, args...)
	}
}

// Infof 使用格式化字符串记录信息级别日志
func (l *StandardLogger) Infof(format string, args ...interface{}) {
	if l.level <= INFO {
		l.infoLog.Printf(format, args...)
	}
}

// Warnf 使用格式化字符串记录警告级别日志
func (l *StandardLogger) Warnf(format string, args ...interface{}) {
	if l.level <= WARN {
		l.warnLog.Printf(format, args...)
	}
}

// Errorf 使用格式化字符串记录错误级别日志
func (l *StandardLogger) Errorf(format string, err error, args ...interface{}) {
	if l.level <= ERROR {
		if err != nil {
			l.errorLog.Printf(format+": %v", append(args, err)...)
		} else {
			l.errorLog.Printf(format, args...)
		}
	}
}

// Fatalf 使用格式化字符串记录致命错误级别日志
func (l *StandardLogger) Fatalf(format string, err error, args ...interface{}) {
	if l.level <= FATAL {
		if err != nil {
			l.fatalLog.Fatalf(format+": %v", append(args, err)...)
		} else {
			l.fatalLog.Fatalf(format, args...)
		}
	}
}
