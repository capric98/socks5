package socks5

import "log"

type DefaultLogger struct{}

type DefaultWarnLogger struct{}

type DefaultNoLogger struct{}

func (l DefaultLogger) Println(a ...interface{}) {
	log.Println(a...)
}
func (l DefaultLogger) Fatal(a ...interface{}) {
	log.Fatal(a...)
}

func (l DefaultWarnLogger) Println(a ...interface{}) {
	if a[0] == WARNLOG || a[0] == FTALLOG {
		log.Println(a...)
	}
}

func (l DefaultWarnLogger) Fatal(a ...interface{}) {
	log.Fatal(a...)
}

func (l DefaultNoLogger) Println(a ...interface{}) {}

func (l DefaultNoLogger) Fatal(a ...interface{}) {
	log.Fatal(a...)
}
