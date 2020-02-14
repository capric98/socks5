package socks5

import (
	"context"
	"sync"

	"github.com/panjf2000/gnet"
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
	HELLO   = 0
	AUTH    = 1
	REQUEST = 2

	INFOLOG = "Info:"
	WARNLOG = "Warn:"
	FTALLOG = "Fatal:"
)

type Logger interface {
	Println(...interface{})
	Fatal(...interface{})
}

type queue struct {
	ring               [][]byte
	head, tail, maxLen int
}

type Request struct {
	CMD      byte
	RSV      byte
	ATYP     byte
	DST_ADDR []byte
	DST_PORT uint16

	conn     *sConn
	status   int
	approved bool
	logger   Logger
}

type sConn struct {
	c       gnet.Conn
	q       *queue
	residue []byte

	wake   chan struct{}
	ctx    context.Context
	cancel func()
}

type Server struct {
	Addr        string
	Port        uint16
	NetType     string
	Multicore   bool
	MaxQueueLen int

	Logger Logger

	*gnet.EventServer
	//pool *goroutine.Pool

	ctx  context.Context
	mu   sync.Mutex
	rMap map[gnet.Conn]*Request

	req chan *Request
}
