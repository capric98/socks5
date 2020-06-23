package socks5

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/capric98/socks5/auth"
)

// Server represents a socks5 server.
type Server struct {
	addr string

	authMu sync.RWMutex
	auths  []auth.Authenticator

	allowUDP   bool
	rewriteBND net.IP
	timeout    time.Duration

	ctx    context.Context
	cancel func()

	reqs     chan *Request
	errs     chan error
	cerrChan chan error
}

// SOpts illustrates options to a server.
type SOpts struct {
	// AllowUDP determines whether the server will accept
	// ASSOCIATE CMD or not.
	AllowUDP bool
	// RewriteBND is only available when AllowUDP is true,
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
	// byte: {5 0 0 4 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 r1 r0}
	// (Means the client should send its udp packet to ipv6
	//  address [::]:(a random port equals {r1*256+r0}))
	// Clients will consider this kind of response as invalid,
	// so you'd better appoint RewriteBND mannually to avoid this.
	RewriteBND net.IP
	// Timeout forces the client to finish tasks in a certain time.
	// For a connection, Timeout = max{Auth + Send CMD + req.Accept()},
	// and after the (*Request).Accpet(), it will be canceled for
	// this connection.
	Timeout time.Duration
	// ErrChan is the channel to get errors or info from the server.
	// Set it to nil to ignore all errors and info.
	ErrChan chan error
}

var (
	defaultOpts = SOpts{
		AllowUDP:   false,
		RewriteBND: nil,
		Timeout:    time.Minute,
		ErrChan:    nil,
	}
)

// NewServer news a server with given address and options.
func NewServer(addr string, opt *SOpts) (s *Server) {
	if opt == nil {
		opt = &defaultOpts
	}
	s = &Server{
		addr:  addr,
		auths: make([]auth.Authenticator, 256),

		allowUDP:   opt.AllowUDP,
		rewriteBND: opt.RewriteBND,
		timeout:    opt.Timeout,

		reqs:     make(chan *Request, 65535),
		errs:     make(chan error, 255),
		cerrChan: opt.ErrChan,
	}
	// Create cancel at Listen().
	// s.ctx, s.cancel = context.WithCancel(context.Background())
	return
}

// SetAuth sets an authenticator to the server.
// It will overwrite exsited Authenticator which
// has the same Method.
func (s *Server) SetAuth(a auth.Authenticator) {
	s.authMu.Lock()
	s.auths[a.Method()] = a
	s.authMu.Unlock()
}

// DelAuth deletes an authenticator of given method.
func (s *Server) DelAuth(method byte) {
	s.authMu.Lock()
	s.auths[method] = nil
	s.authMu.Unlock()
}

// GetAuth gets an authenticator from the server of given Method.
// If given Method has no Authenticator, it will return nil.
func (s *Server) GetAuth(method byte) (a auth.Authenticator) {
	s.authMu.RLock()
	a = s.auths[method]
	s.authMu.RUnlock()
	return
}

// Listen starts a server.
func (s *Server) Listen() error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	bctx, bcancel := context.WithCancel(context.Background())
	s.ctx = bctx
	s.cancel = func() {
		bcancel()
		l.Close()
	}

	cc := make(chan net.Conn)
	// accept connections
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
	// handle connections
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

	// handle err
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case e := <-s.errs:
				if s.cerrChan != nil {
					select {
					case s.cerrChan <- e:
					default:
						// just in case
					}
				}
			}
		}
	}()
	return nil
}

// Stop stops a server.
// Stop a server before Listen() will cause panic.
func (s *Server) Stop() {
	s.cancel()
	if s.cerrChan != nil {
		close(s.cerrChan)
	}
}

// Accept returns a valid request.
// If the server is stopped, it will return nil.
func (s *Server) Accept() (req *Request) {
	select {
	case req = <-s.reqs:
	case <-s.ctx.Done():
	}
	return
}

func (s *Server) handle(conn net.Conn) {
	defer func() {
		if p := recover(); p != nil {
			s.errs <- fmt.Errorf("denied connection from %v - %v", conn.RemoteAddr(), p)
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
		panic(fmt.Errorf("invalid socks version: %v", head[0]))
	}

	clientMethods := make([]byte, int(head[1]))
	if _, e := conn.Read(clientMethods); e != nil {
		panic(e)
	}

	var authenticator auth.Authenticator
	s.authMu.RLock()
	for i := range clientMethods {
		if s.auths[clientMethods[i]] != nil {
			authenticator = s.auths[clientMethods[i]]
			break
		}
	}
	s.authMu.RUnlock()
	if authenticator == nil {
		_, _ = conn.Write([]byte{VERSION, NOACCEPT})
		panic("no accept Method")
	}
	if _, e := conn.Write([]byte{VERSION, authenticator.Method()}); e != nil {
		panic(e)
	}
	if !authenticator.Check(conn) {
		panic(fmt.Errorf("method %v auth fail", authenticator.Method()))
	}

	// Handle CMD
	cmdHead := make([]byte, 4)
	if _, e := conn.Read(cmdHead); e != nil {
		panic(e)
	}
	if cmdHead[0] != VERSION {
		panic(fmt.Errorf("invalid socks version: %v", cmdHead[0]))
	}

	req := &Request{
		cmd:  cmdHead[1],
		rsv:  cmdHead[2],
		atyp: cmdHead[3],
		clt:  conn,
		errs: s.errs,
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
