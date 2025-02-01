package main

import (
	"log"
)

type LogLevel string

const (
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

var logLevel = getLogLevel()

func getLogLevel() LogLevel {
	level := LogLevel(getEnv("LOG_LEVEL", string(LogLevelInfo)))
	switch level {
	case LogLevelInfo, LogLevelWarn, LogLevelError:
		return level
	default:
		return LogLevelInfo
	}
}

func shouldLog(level LogLevel) bool {
	switch level {
	case LogLevelError:
		return true
	case LogLevelWarn:
		return logLevel != LogLevelError
	case LogLevelInfo:
		return logLevel != LogLevelError && logLevel != LogLevelWarn
	default:
		return false
	}
}

func logInfo(format string, v ...interface{}) {
	if !shouldLog(LogLevelInfo) {
		return
	}
	log.Printf(format+"\n", v...)
}

func logWarn(format string, v ...interface{}) {
	if !shouldLog(LogLevelWarn) {
		return
	}
	log.Printf("[Warn]: "+format+"\n", v...)
}

func logError(format string, v ...interface{}) {
	log.Printf("[Error]: "+format+"\n", v...)
}
