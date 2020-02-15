package socks5

import (
	"context"
	"net"
	"sync"
	"time"
)

const (
	VERSION = byte(5)
)

const (
	NOAUTH byte = iota
	_
	PSSWD

	NOACCEPT = byte(255)
)

const (
	RSV byte = iota
	CONNECT
	BIND
	ASSOCIATE
)

const (
	_ byte = iota
	ATYPIPv4
	_
	ATYPDOMAIN
	ATYPIPv6
)

const (
	REPSUCCESS byte = iota
	NORMALFAIL
	_
	NET_UNREACHABLE
	HOST_UNREACHABLE
	REFUSED
	TIMEOUT

	INFOLOG = "Info:"
	WARNLOG = "Warn:"
	FTALLOG = "Fatal:"
)

type frame struct {
	b []byte
	n int
}

type Logger interface {
	Println(...interface{})
	Fatal(...interface{})
}

// type queue struct {
// 	head, tail *Frame
// 	qlen       int32
// }

type Request struct {
	CMD      byte
	RSV      byte
	ATYP     byte
	DST_ADDR []byte
	DST_PORT uint16

	clt, srv net.Conn
	ctx      context.Context
	cancel   func()
	logger   Logger
}

type Server struct {
	Addr    string
	Port    uint16
	NetType string

	Auth  bool
	Ident map[string]string

	TimeOut time.Duration
	Logger  Logger

	ctx context.Context
	mu  sync.Mutex
	req chan *Request
}
