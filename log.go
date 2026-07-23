package main

import (
	"log"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

var logLevel = getLogLevel()

func getLogLevel() LogLevel {
	level := LogLevel(getEnv("LOG_LEVEL", string(LogLevelInfo)))
	switch level {
	case LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError:
		return level
	default:
		return LogLevelInfo
	}
}

func shouldLog(level LogLevel) bool {
	switch logLevel {
	case LogLevelDebug:
		return true
	case LogLevelInfo:
		return level != LogLevelDebug
	case LogLevelWarn:
		return level == LogLevelWarn || level == LogLevelError
	case LogLevelError:
		return level == LogLevelError
	default:
		return level != LogLevelDebug
	}
}

func logDebug(format string, v ...interface{}) {
	if !shouldLog(LogLevelDebug) {
		return
	}
	log.Printf("[Debug]: "+format+"\n", v...)
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
