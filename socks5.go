// Package socks5 provides a convenient way to
// implement a socks5 server with flexible backends.
package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// Listen starts the server and listenes Addr:Port.
// If the server failed to listen, it would return an error.
func (s *Server) Listen() error {
	if e := s.init(); e != nil {
		return e
	}

	l, err := net.Listen("tcp", s.Addr+":"+strconv.Itoa(int(s.Port)))
	if err != nil {
		return err
	}
	s.Logger.Log(INFO, "Start listening %v.", l.Addr())

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
				s.Logger.Log(WARN, "Failed to accept a connection: %v.", err)
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

// Accept returns an authorized CMD request from the client.
// Accept from a server which was shutdown will return a nil Request.
func (s *Server) Accept() *Request {
	select {
	case <-s.ctx.Done():
		return nil
	case req := <-s.req:
		return req
	}
}

// Shutdown stops the server.
func (s *Server) Shutdown() {
	// stop() is the func from context.WithCancel(context.Background())
	s.stop()
}

func (s *Server) handle(conn net.Conn) {
	var e error
	var n int

	defer func() {
		if e != nil {
			s.Logger.Log(WARN, "Connection from %v raised an error: %v.", conn.RemoteAddr(), e)
			conn.Close()
		}
	}()

	one := make([]byte, 1)

	// We will cancel this deadline in (*Request).Success method.
	// Remember to cancel in (*Server).handleUDP too.
	_ = conn.SetDeadline(time.Now().Add(s.TimeOut))

	if _, e = conn.Read(one); e != nil {
		return
	}
	if one[0] != VERSION {
		e = errors.New("Wrong socks version!")
		return
	}
	if _, e = conn.Read(one); e != nil {
		return
	}

	clientMethods := make([]byte, int(one[0]))
	if _, e = conn.Read(clientMethods); e != nil {
		return
	}

	reply := []byte{VERSION, NOACCEPT}
	for i := 0; i < int(one[0]); i++ {
		if s.authMethod[clientMethods[i]] {
			reply[1] = clientMethods[i]
			break
		}
	}

	if n, e = conn.Write(reply); e != nil {
		return
	}
	if n != 2 {
		e = io.ErrShortWrite
		return
	}

	var authPassed bool
	var authResp []byte

	// Authentication
	switch reply[1] {
	case NOAUTH:
		authPassed, authResp = true, nil
	case PSSWD:
		authPassed, authResp = s.psswdauth(conn)
	case NOACCEPT:
		_ = conn.Close()
		return
	}

	if authPassed {
		if n, e := conn.Write(authResp); e != nil || n != len(authResp) {
			conn.Close()
			return
		}
	} else {
		s.Logger.Log(WARN, "Connection from %v failed to pass the authentication.", conn.RemoteAddr())
		_, _ = conn.Write(authResp)
		conn.Close()
		return
	}

	// Handle CMD
	cmdHead := make([]byte, 4)
	if _, e = conn.Read(cmdHead); e != nil {
		return
	}
	if cmdHead[0] != VERSION {
		e = errors.New("Wrong socks version!")
		return
	}

	req := &Request{
		CMD:  cmdHead[1],
		RSV:  cmdHead[2],
		ATYP: cmdHead[3],

		clt:    conn,
		logger: s.Logger,
		udpAck: make(chan net.PacketConn),
	}
	var residue int
	switch req.ATYP {
	case ATYPIPv4:
		residue = 6
	case ATYPIPv6:
		residue = 18
	case ATYPDOMAIN:
		if _, e = conn.Read(one); e != nil {
			return
		}
		residue = int(one[0]) + 2
	}
	resb := make([]byte, residue)
	if _, e = conn.Read(resb); e != nil {
		return
	}
	req.DST_PORT = uint16(resb[residue-2])<<8 + uint16(resb[residue-1])
	req.DST_ADDR = resb[:residue-2]
	req.ctx, req.cancel = context.WithCancel(s.ctx)

	switch cmdHead[1] {
	case CONNECT:
	case ASSOCIATE:
		if !s.AllowUDP {
			e = errors.New("Do not support ASSOCIATE due to rule set.")
			_, _ = conn.Write([]byte{VERSION, RULEFAIL, RSV, ATYPIPv4, 0, 0, 0, 0, 0, 0})
			return
		} else {
			go s.handleUDP(req)
		}
	default:
		// No support for BIND yet.
		e = errors.New("Unknown CMD:" + string(cmdHead[1:1]))
		_, _ = conn.Write([]byte{VERSION, NOSUPPORT, RSV, ATYPIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	s.Logger.Log(INFO, "Accept the connection from %v.", conn.RemoteAddr())
	req.watch()
	s.req <- req
}

func (s *Server) handleUDP(req *Request) {
	defer func() { _ = recover() }()
	defer req.cancel()

	conn := req.clt

	spl := <-req.udpAck
	if spl == nil {
		return
	}

	pl, e := net.ListenPacket("udp", s.Addr+":")
	if e != nil {
		_, _ = conn.Write([]byte{VERSION, NORMALFAIL, RSV, ATYPIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer pl.Close()

	laddr := pl.LocalAddr()
	if s.RewriteBND != nil {
		// Rewrite
		port := laddr.(*net.UDPAddr).Port
		laddr = net.Addr(&net.UDPAddr{
			IP:   s.RewriteBND,
			Port: port,
		})
	}
	resp := genResp(laddr)
	//s.Logger.Println(INFOLOG, "ASSOCIATE response:", resp)

	if n, e := conn.Write(resp); n != len(resp) || e != nil {
		s.Logger.Log(INFO, "Connection from %v was expected to write %v byte(s) and wrote %v byte(s) with err: %v.", conn.RemoteAddr(), len(resp), n, e)
		return
	}

	addrChan := make(chan net.Addr, 10)
	defer close(addrChan)

	go func() {
		defer func() { _ = recover() }()
		buffer := make([]byte, 16*1024)
		var n int
		var re, we error
		var taddr net.Addr

		select {
		case taddr = <-addrChan:
		case <-req.ctx.Done():
			return
		}

		head := append([]byte{0, 0, 0}, resp[3:]...)
		headlen := len(head)

		for re == nil && we == nil {
			_ = spl.SetReadDeadline(time.Now().Add(s.TimeOut))
			_ = pl.SetWriteDeadline(time.Now().Add(s.TimeOut))
			n, _, re = spl.ReadFrom(buffer)

			head = append(head, buffer[:n]...)

			select {
			case taddr = <-addrChan:
				if taddr == nil {
					return
				}
			default:
			}
			_, we = pl.WriteTo(head, taddr)
			head = head[:headlen]
		}
	}()

	buffer := make([]byte, 16*1024)
	var n, domainEnd int
	var re, we error
	var caddr, raddr net.Addr
	for we == nil && re == nil {
		_ = pl.SetReadDeadline(time.Now().Add(s.TimeOut))
		_ = spl.SetWriteDeadline(time.Now().Add(s.TimeOut))
		n, caddr, re = pl.ReadFrom(buffer)

		if !caddr.(*net.UDPAddr).IP.Equal(conn.RemoteAddr().(*net.TCPAddr).IP) {
			continue
		}
		if n < 11 {
			continue
		}
		if buffer[0]+buffer[1]+buffer[2] != 0 {
			continue
		}
		select {
		case addrChan <- caddr:
		default:
		}

		switch buffer[3] {
		case ATYPIPv4:
			_, we = spl.WriteTo(buffer[10:n], &net.UDPAddr{
				IP:   net.IP(buffer[4:8]),
				Port: int(buffer[8])<<8 + int(buffer[9]),
			})
		case ATYPIPv6:
			_, we = spl.WriteTo(buffer[22:n], &net.UDPAddr{
				IP:   net.IP(buffer[4:20]),
				Port: int(buffer[20])<<8 + int(buffer[21]),
			})
		case ATYPDOMAIN:
			domainEnd = 5 + int(buffer[4])
			raddr, _ = net.ResolveUDPAddr("udp", string(buffer[5:domainEnd])+":"+strconv.Itoa(int(buffer[domainEnd])<<8+int(buffer[domainEnd+1])))
			_, we = spl.WriteTo(buffer[domainEnd+2:n], raddr)
		}
	}
}
