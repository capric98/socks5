package socks5

import "log"

type defaultLogger struct{}

type NoLogger struct{}

func (l defaultLogger) Log(level, format string, v ...interface{}) {
	log.Printf(format, v...)
}

// Log of NoLogger outputs nothing.
func (l NoLogger) Log(level, format string, v ...interface{}) {}
