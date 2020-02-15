package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

func (s *Server) Listen() error {
	s.init()

	l, err := net.Listen(s.NetType, s.Addr+":"+strconv.Itoa(int(s.Port)))
	if err != nil {
		s.Logger.Fatal(err)
		return err
	}
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
				conn, err := l.Accept()
				if err != nil {
					s.Logger.Println(WARNLOG, "net Accept:", err)
					continue
				}
				go s.handle(conn)
			}
		}
	}()
	return nil
}

func (s *Server) Accept() *Request {
	return <-s.req
}

func (s *Server) handle(conn net.Conn) {
	var e error
	var n int

	defer func() {
		if e != nil {
			s.Logger.Println(INFOLOG, conn.RemoteAddr().String, "raised an error", e)
			conn.Close()
		}
	}()

	one := make([]byte, 1)

	// We will cancel this deadline in (*Request)Success method.
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
	if s.Auth {
		for i := 0; i < int(one[0]); i++ {
			if clientMethods[i] == PSSWD {
				reply[1] = PSSWD
				break
			}
		}
	} else {
		for i := 0; i < int(one[0]); i++ {
			if clientMethods[i] == NOAUTH {
				reply[1] = NOAUTH
				break
			}
		}
	}

	if n, e = conn.Write(reply); e != nil {
		return
	}
	if n != 2 {
		e = io.ErrShortWrite
		return
	}
	if reply[1] == NOACCEPT {
		e = io.EOF
		return
	}

	if s.Auth {
		// TODO: authentication
		if s.auth(conn) {
			if n, e := conn.Write([]byte{VERSION, 0}); e != nil || n != 2 {
				conn.Close()
				return
			}
		} else {
			_, _ = conn.Write([]byte{VERSION, 1})
			conn.Close()
			return
		}
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
	// No support for BIND yet.
	if cmdHead[1] == 2 {
		e = errors.New("DO NOT SUPPORT BIND")
		return
	}
	req := &Request{
		CMD:  cmdHead[1],
		RSV:  cmdHead[2],
		ATYP: cmdHead[3],

		clt:    conn,
		logger: s.Logger,
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
	s.req <- req
}

func (s *Server) auth(conn net.Conn) bool {
	head := make([]byte, 2)
	if n, e := conn.Read(head); n != 2 || e != nil || head[0] != 1 {
		return false
	}
	userbyte := make([]byte, int(head[1])+1)
	if n, e := conn.Read(userbyte); n != int(head[1])+1 || e != nil {
		return false
	}
	password := make([]byte, int(userbyte[int(head[1])]))
	if n, e := conn.Read(password); n != int(userbyte[int(head[1])]) || e != nil {
		return false
	}

	return s.Ident[string(userbyte[:int(head[1])])] == string(password)
}
