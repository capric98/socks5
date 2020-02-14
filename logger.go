package socks5

import "log"

type DefaultLogger struct{}

type DefaultNoLogger struct{}

func (l DefaultLogger) Println(a ...interface{}) {
	log.Println(a...)
}
func (l DefaultLogger) Fatal(a ...interface{}) {
	log.Fatal(a...)
}

func (l DefaultNoLogger) Println(a ...interface{}) {}

func (l DefaultNoLogger) Fatal(a ...interface{}) {
	log.Fatal(a...)
}
