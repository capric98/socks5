package socks5

import (
	"context"
	"fmt"
	"log"
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

	reqs chan *Request
	errs chan error
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
func NewServer(addr string, port int, opt *SOpts) (s *Server) {
	if opt == nil {
		opt = &defaultOpts
	}
	s = &Server{
		addr:  addr,
		port:  int(uint16(port)),
		auths: make(map[byte]auth.Authenticator),

		allowUDP:   opt.AllowUDP,
		rewriteBND: opt.RewriteBND,
		timeout:    opt.Timeout,

		reqs: make(chan *Request, 65535),
		errs: make(chan error, 255),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return
}

// AddAuth adds an authenticator to the server.
func (s *Server) AddAuth(a auth.Authenticator) {
	s.auths[a.Method()] = a
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
				s.errs <- err
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

	// TODO: handle errs
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case e := <-s.errs:
				log.Println(e)
			}
		}
	}()
	return nil
}

// Stop stopss a server.
func (s *Server) Stop() {
	s.cancel()
}

// Accepet returns a valid request.
func (s *Server) Accepet() (req *Request) {
	select {
	case req = <-s.reqs:
	case <-s.ctx.Done():
	}
	return
}

func (s *Server) handle(conn net.Conn) {
	//var n int

	defer func() {
		if p := recover(); p != nil {
			s.errs <- fmt.Errorf("%v", p)
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
	if !authenticator.Check(conn) {
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

	req := &Request{
		cmd:  cmdHead[1],
		rsv:  cmdHead[2],
		atyp: cmdHead[3],
		clt:  conn,
	}

	var residue int
	switch req.atyp {
	case IPV4T:
		residue = 6
	case IPV6T:
		residue = 18
	case DOMAIN:
		one := make([]byte, 1)
		if _, e := conn.Read(one); e != nil {
			panic(e)
		}
		residue = int(one[0]) + 2
	}
	resbyte := make([]byte, residue)
	if _, e := conn.Read(resbyte); e != nil {
		panic(e)
	}
	req.dstPort = uint16(resbyte[residue-2])<<8 + uint16(resbyte[residue-1])
	req.dstAddr = resbyte[:residue-2]
	req.ctx, req.cancel = context.WithCancel(s.ctx)

	switch cmdHead[1] {
	case CONNECT:
	case ASSOCIATE:
		if s.allowUDP {
			req.pconn = make(chan net.PacketConn)
			go s.associate(req)
		} else {
			_, _ = conn.Write([]byte{VERSION, FORBID, RSV, IPV4T, 0, 0, 0, 0, 0, 0})
			conn.Close()
			return
		}
	default:
		// No support for BIND yet.
		_, _ = conn.Write([]byte{VERSION, NSUPPORT, RSV, IPV4T, 0, 0, 0, 0, 0, 0})
		conn.Close()
		return
	}
	req.watch()
	s.reqs <- req
}
