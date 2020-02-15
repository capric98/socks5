package socks5

import (
	"io"
	"net"
	"time"
)

func (r *Request) Fail(e error) {
	r.cancel()
}

func (r *Request) Success(conn net.Conn) {
	r.srv = conn
	resp := []byte{VERSION, REPSUCCESS, RSV, ATYPIPv4}

	var laddr net.IP
	var port uint16
	switch addr := conn.LocalAddr().(type) {
	case *net.UDPAddr:
		laddr = addr.IP
		port = uint16(addr.Port)
	case *net.TCPAddr:
		laddr = addr.IP
		port = uint16(addr.Port)
	}

	if laddr.To4() != nil {
		resp = append(resp, laddr.To4()...)
	} else {
		resp[3] = ATYPIPv6
		resp = append(resp, laddr.To16()...)
	}
	resp = append(resp, byte(port>>8), byte(port&0xff))

	if n, e := r.clt.Write(resp); n != len(resp) || e != nil {
		r.logger.Println(INFOLOG, conn.RemoteAddr(), "was expected to write", len(resp), "but wrote", n, "bytes with err", e)
		r.shutdown()
	}
	// Cancel Deadline
	_ = r.clt.SetDeadline(time.Time{})
	go r.pipe()
}

func (r *Request) shutdown() {
	r.cancel()
	_ = r.clt.Close()
	_ = r.srv.Close()
}

func (r *Request) pipe() {
	go io.Copy(r.clt, r.srv)
	go io.Copy(r.srv, r.clt)
}
