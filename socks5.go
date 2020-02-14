package socks5

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/panjf2000/gnet"
)

func (s *Server) Listen() {
	s.init()
	go func() {
		s.Logger.Fatal(gnet.Serve(s, s.NetType+"://"+s.Addr+":"+strconv.Itoa(int(s.Port)), gnet.WithMulticore(s.Multicore)))
	}()
}

func (s *Server) Accept() *Request {
	return <-s.req
}

func (r *Request) Success(conn net.Conn) {
	oldReply(r, conn)
	go r.pipe(conn)
}

func (r *Request) Fail(e error) {
	r.Error(e)
}

func (r *Request) Error(e error) {
	r.logger.Println(INFOLOG, "Connection from", r.conn.c.RemoteAddr(), "raised an error:", e)
}

func (s *Server) OnInitComplete(srv gnet.Server) (action gnet.Action) {
	s.Logger.Println(INFOLOG, "Start listening", s.NetType, srv.Addr.String(), "withMulticore", srv.Multicore, ".")
	return
}

func (s *Server) OnOpened(c gnet.Conn) (out []byte, action gnet.Action) {
	s.Logger.Println(INFOLOG, "New connection from", c.RemoteAddr())

	r := &Request{
		conn: &sConn{
			c: c,
			q: &queue{
				head:   0,
				tail:   0,
				maxLen: s.MaxQueueLen,
				ring:   make([][]byte, s.MaxQueueLen),
			},
			wake: make(chan struct{}),
		},
		logger: s.Logger,
	}
	for i := 0; i < s.MaxQueueLen; i++ {
		r.conn.q.ring[i] = make([]byte, 0, 100)
	}
	r.conn.ctx, r.conn.cancel = context.WithCancel(s.ctx)
	s.rMap[c] = r

	return
}

func (s *Server) OnClosed(c gnet.Conn, e error) (action gnet.Action) {
	req := s.rMap[c]
	req.conn.cancel()

	s.mu.Lock()
	delete(s.rMap, c)
	s.mu.Unlock()

	if e != nil && e != io.EOF {
		s.Logger.Println(WARNLOG, "Connection from", c.RemoteAddr(), "was closed by error:", e)
	}
	return
}

func (s *Server) React(frame []byte, c gnet.Conn) (out []byte, action gnet.Action) {
	req := s.rMap[c]

	select {
	case <-req.conn.ctx.Done():
		action = gnet.Close
		return
	default:
		if len(frame) == 0 {
			return
		}
	}

	if req.approved {
		tmp := req.conn.q.tail
		req.conn.q.ring[tmp] = append(req.conn.q.ring[tmp], frame...)
		tmp++
		if tmp == req.conn.q.maxLen {
			tmp = 0
		}
		if tmp == req.conn.q.head {
			s.Logger.Println(WARNLOG, "Connection from", c.RemoteAddr(), "queue overflow.")
			action = gnet.Close
			return
		}
		req.conn.q.tail = tmp
		select {
		case req.conn.wake <- struct{}{}:
		default:
		}
		// if frame[0] == 5 && frame[1] == 1 && frame[2] == 0 {
		// 	s.Logger.Println("In normal:", frame)
		// }
	} else {
		if len(frame) < 3 {
			action = gnet.Close
			return
		}
		if frame[0] != 5 {
			// Only support socks5 protocol.
			action = gnet.Close
		}
		if req.status == HELLO {
			if 2+int(frame[1]) != len(frame) {
				action = gnet.Close
				return
			}
			for i := 2; i < len(frame); i++ {
				if frame[i] == 0 {
					out = []byte{5, 0}
					req.status = REQUEST
				}
			}
			// s.Logger.Println("Client hello.")
			// s.Logger.Println(frame)
			// s.Logger.Println(out)
			return
		}
		if req.status == REQUEST {
			if len(frame) < 10 {
				action = gnet.Close
				return
			}

			req.CMD = frame[1]
			req.RSV = frame[2]
			req.ATYP = frame[3]

			var pos int
			switch req.ATYP {
			case 1:
				pos = 8
			case 4:
				pos = 20
			case 3:
				pos = 4 + int(frame[4])
				frame = frame[1:]
			default:
				action = gnet.Close
				return
			}

			if len(frame) != pos+2 {
				action = gnet.Close
				return
			}
			req.DST_ADDR = append([]byte{}, frame[4:pos]...)
			req.DST_PORT = uint16(frame[pos])<<8 + uint16(frame[pos+1])

			req.approved = true
			s.req <- req
		}
	}

	return
}

func oldReply(r *Request, conn net.Conn) {
	resp := []byte{5, 0, 0}
	var remoteAddr net.IP
	var remotePort uint16
	switch addr := conn.RemoteAddr().(type) {
	case *net.UDPAddr:
		remoteAddr = addr.IP
		remotePort = uint16(addr.Port)
	case *net.TCPAddr:
		remoteAddr = addr.IP
		remotePort = uint16(addr.Port)
	}

	if remoteAddr.To4() != nil {
		resp = append(append(resp, 1), []byte(remoteAddr.To4())...)
	} else {
		resp = append(append(resp, 4), []byte(remoteAddr.To16())...)
	}
	resp = append(resp, byte(remotePort>>8), byte(remotePort%256))

	log.Println("Success Resp:", resp)
	_, _ = r.conn.Write(resp)
}
