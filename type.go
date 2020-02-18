package socks5

import (
	"context"
	"net"
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
	RULEFAIL
	NET_UNREACHABLE
	HOST_UNREACHABLE
	REFUSED
	TIMEOUT
	NOSUPPORT

	INFO  = "Info"
	WARN  = "Warn"
	FATAL = "Fatal"
)

type frame struct {
	b []byte
	n int
}

// Logger is the interface that wraps Log method.
type Logger interface {
	Log(level string, format string, v ...interface{})
}

// Request represents an authorized CMD request from the client.
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

	udpAck chan net.PacketConn
}

// Server represents an instance of socks5 server.
type Server struct {
	Addr     string
	Port     uint16
	AllowUDP bool

	// This field is only available when AllowUDP is true,
	// and the server is behind a NAT network, with all
	// its UDP ports forwarded, and serving ASSOCIATE CMD
	// from clients who are not in the same intranet as the
	// server.
	// In this situation, you will want to rewrite BND.ADDR
	// in server's reply message in order to make clients
	// able to send UDP packet to BND.ADDR:BND.PORT.
	//
	// There is another situation, that you do not specify
	// Addr, in this case, "net" will listen [::] by default,
	// result in ASSOCIATE response be:
	// byte: {5 0 0 4 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 rand rand}
	// Clients will consider this kind of response as invalid,
	// so you'd better appoint RewriteBND mannually to avoid this.
	RewriteBND net.IP

	Auth  bool
	Ident map[string]string

	TimeOut time.Duration
	Logger  Logger

	ctx  context.Context
	stop func()

	req chan *Request
}
