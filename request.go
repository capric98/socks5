package socks5

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

// Success approves the Request with an interface, the interface
// MUST be able to be converted to a net.Conn(CONNECT) or a
// net.PacketConn(ASSOCIATE).
func (r *Request) Success(i interface{}) {
	if i == nil {
		r.Fail(nil)
	}

	switch r.CMD {
	case CONNECT:
		conn, ok := i.(net.Conn)
		if ok {
			r.succCONNECT(conn)
		} else {
			r.Fail(errors.Errorf("CONNECT got %T rather than net.Conn .", i))
		}
	case ASSOCIATE:
		pl, ok := i.(net.PacketConn)
		if ok {
			r.succASSOCIATE(pl)
		} else {
			r.Fail(errors.Errorf("ASSOCIATE got %T rather than net.PacketConn .", i))
		}
	default:
		r.Fail(errors.New("CMD(" + strconv.Itoa(int(r.CMD)) + ") unsupported."))
	}
}

// Fail denies the Request with a given error, the server will write a response
// of NormalFail message to the client, then close the connection.
func (r *Request) Fail(e error) {
	r.logger.Log(INFO, "Connection from %v failed because %v.", r.CltAddr(), e)

	resp := genResp(r.clt.LocalAddr())
	resp[1] = NORMALFAIL
	_, _ = r.clt.Write(resp)

	close(r.udpAck)
	r.cancel()
}

// CltAddr returns the client address of the Request.
func (r *Request) CltAddr() net.Addr {
	return r.clt.RemoteAddr()
}

func (r *Request) succCONNECT(conn net.Conn) {
	r.srv = conn

	resp := genResp(r.clt.LocalAddr())

	if n, e := r.clt.Write(resp); n != len(resp) || e != nil {
		r.logger.Log(WARN, "Connection from %v was expected to write %v byte(s) and wrote %v byte(s) with err %v.", conn.RemoteAddr(), len(resp), n, e)
		r.cancel()
	}
	// Cancel Deadline
	_ = r.clt.SetDeadline(time.Time{})

	r.pipe()
}

func (r *Request) succASSOCIATE(pl net.PacketConn) {
	// Cancel Deadline
	_ = r.clt.SetDeadline(time.Time{})

	r.udpAck <- pl
}

func (r *Request) watch() {
	go func() {
		<-r.ctx.Done()
		if r.srv == nil {
			r.logger.Log(INFO, "Connection from %v was done.", r.CltAddr())
		} else {
			r.logger.Log(INFO, "Connection %v -> %v was done.", r.CltAddr(), r.srv.RemoteAddr())
			_ = r.srv.Close()
		}
		_ = r.clt.Close()
	}()
}

func (r *Request) pipe() {
	go bufferedCopy(r.clt, r.srv, r.ctx, r.cancel)
	go bufferedCopy(r.srv, r.clt, r.ctx, r.cancel)
}

func bufferedCopy(dst, src net.Conn, ctx context.Context, cancel func()) {
	defer cancel()

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
				return
			}
		}
	}()

	for wf = range wc {
		wn, we = dst.Write(wf.b[:wf.n])
		rc <- wf
		if we != nil || wn != wf.n {
			close(rc)
			return
		}
	}
}

func genResp(iaddr net.Addr) []byte {
	resp := []byte{VERSION, REPSUCCESS, RSV, RSV}

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
		// laddr is an IPv4 address.
		resp[3] = ATYPIPv4
		resp = append(resp, laddr.To4()...)
	} else {
		// laddr is an IPv6 address.
		resp[3] = ATYPIPv6
		resp = append(resp, laddr.To16()...)
	}
	resp = append(resp, byte(port>>8), byte(port&0xff))

	return resp
}
