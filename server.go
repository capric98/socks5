package socks5

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/capric98/socks5/auth"
)

// Server represents a socks5 server.
type Server struct {
	addr  string
	port  int
	auths map[byte]auth.Authenticator

	allowUDP   bool
	rewriteBND net.IP
	timeout    time.Duration

	ctx    context.Context
	cancel func()
}

// SOpts illustrates options to a server.
type SOpts struct {
	AllowUDP   bool
	RewriteBND net.IP
	Timeout    time.Duration
}

var (
	defaultOpts = SOpts{
		AllowUDP:   false,
		RewriteBND: nil,
		Timeout:    time.Minute,
	}
)

// NewServer news a server.
func NewServer(addr string, opt *SOpts) (s *Server) {
	if opt == nil {
		opt = &defaultOpts
	}
	s = &Server{
		allowUDP:   opt.AllowUDP,
		rewriteBND: opt.RewriteBND,
		timeout:    opt.Timeout,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return
}

// Listen starts a server.
func (s *Server) Listen() error {
	l, err := net.Listen("tcp", s.addr+":"+strconv.Itoa(int(s.port)))
	if err != nil {
		return err
	}

	cc := make(chan net.Conn)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				if e, ok := err.(*net.OpError); ok {
					// I cannot use internal.poll.ErrNetClosing since its an internal package.
					if e.Unwrap() != nil && e.Unwrap().Error() == "use of closed network connection" {
						// l was closed, quit this goroutine
						return
					}
				}
				// s.Logger.Log(WARN, "Failed to accept a connection: %v.", err)
			} else {
				cc <- conn
			}
		}
	}()
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				_ = l.Close()
				return
			case conn := <-cc:
				go s.handle(conn)
			}
		}
	}()
	return nil
}

// Stop stopss a server.
func (s *Server) Stop() {
	s.cancel()
}

func (s *Server) handle(conn net.Conn) {
	//var n int

	defer func() {
		if p := recover(); p != nil {
			conn.Close()
		}
	}()

	// We will cancel this deadline in (*Request).Success method.
	// Remember to cancel in (*Server).handleUDP too.
	_ = conn.SetDeadline(time.Now().Add(s.timeout))

	head := make([]byte, 2)
	if _, e := conn.Read(head); e != nil {
		panic(e)
	}
	if head[0] != VERSION {
		panic(head[0])
	}

	clientMethods := make([]byte, int(head[1]))
	if _, e := conn.Read(clientMethods); e != nil {
		panic(e)
	}

	var authenticator auth.Authenticator
	for i := range clientMethods {
		if s.auths[clientMethods[i]] != nil {
			authenticator = s.auths[clientMethods[i]]
			break
		}
	}
	if authenticator == nil {
		_, _ = conn.Write([]byte{VERSION, NOACCEPT})
		panic(NOACCEPT)
	}
	if _, e := conn.Write([]byte{VERSION, authenticator.Method()}); e != nil {
		panic(e)
	}
	if authenticator.Check(conn) {
		panic("Auth Fail")
	}

	// Handle CMD
	cmdHead := make([]byte, 4)
	if _, e := conn.Read(cmdHead); e != nil {
		panic(e)
	}
	if cmdHead[0] != VERSION {
		panic(cmdHead[0])
	}
}
