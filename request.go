package socks5

import (
	"context"
	"net"
	"strconv"
	"time"
)

func (r *Request) Fail(e error) {
	r.cancel()
}

func (r *Request) Success(conn net.Conn) {
	r.srv = conn

	if r.CMD != CONNECT {
		r.logger.Println(WARNLOG, "Request from", r.clt.RemoteAddr(), "is not a CONNECT CMD.", "("+strconv.Itoa(int(r.CMD))+")")
		r.cancel()
		return
	}

	resp := genResp(conn.LocalAddr())

	if n, e := r.clt.Write(resp); n != len(resp) || e != nil {
		r.logger.Println(INFOLOG, conn.RemoteAddr(), "was expected to write", len(resp), "byte(s) but wrote", n, "byte(s) with err", e)
		r.cancel()
	}
	// Cancel Deadline
	_ = r.clt.SetDeadline(time.Time{})

	r.pipe()
}

func (r *Request) SuccessUDP(pl net.PacketConn) {
	if r.CMD != ASSOCIATE {
		r.logger.Println(INFOLOG, "Request from", r.clt.RemoteAddr(), "is not an ASSOCIATE CMD.", "("+strconv.Itoa(int(r.CMD))+")")
		r.cancel()
		//close(r.udpAck)
	} else {
		r.udpAck <- pl
	}
}

func (r *Request) FailUDP(e error) {
	r.logger.Println(INFOLOG, "ASSOCIATE from", r.clt.RemoteAddr, "failed because", e)
	close(r.udpAck)
}

func (r *Request) watch() {
	go func() {
		<-r.ctx.Done()
		if r.clt != nil && r.srv != nil {
			r.logger.Println(INFOLOG, "Connection", r.clt.RemoteAddr(), "->", r.srv.RemoteAddr(), "was done.")
		}
		if r.clt != nil {
			_ = r.clt.Close()
		}
		if r.srv != nil {
			_ = r.srv.Close()
		}
	}()
}

func (r *Request) pipe() {
	go bufferedCopy(r.clt, r.srv, r.ctx, r.cancel)
	go bufferedCopy(r.srv, r.clt, r.ctx, r.cancel)
}

func bufferedCopy(dst, src net.Conn, ctx context.Context, cancel func()) {
	rc := make(chan *frame, 2)
	wc := make(chan *frame, 2)
	rc <- &frame{b: make([]byte, 16*1024)}
	rc <- &frame{b: make([]byte, 16*1024)}

	var wn int
	var re, we error
	var rf, wf *frame

	go func() {
		for rf = range rc {
			rf.n, re = src.Read(rf.b)
			wc <- rf
			if re != nil {
				close(wc)
				cancel()
				return
			}
		}
	}()

	for wf = range wc {
		wn, we = dst.Write(wf.b[:wf.n])
		if we != nil || wn != wf.n {
			close(rc)
			cancel()
			return
		}
		rc <- wf
	}
}

func genResp(iaddr net.Addr) []byte {
	resp := []byte{VERSION, REPSUCCESS, RSV, ATYPIPv4}

	var laddr net.IP
	var port uint16
	switch addr := iaddr.(type) {
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

	return resp
}

func (r *Request) CltAddr() net.Addr {
	return r.clt.RemoteAddr()
}