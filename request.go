package socks5

import (
	"context"
	"net"
)

var (
	bufSize = 4 * 1024
)

// Request illustrate a valid socks5 request.
type Request struct {
	cmd, rsv, atyp byte

	dstPort uint16
	dstAddr []byte
	clt     net.Conn
	pconn   chan net.PacketConn // For associate only.

	ctx    context.Context
	cancel func()
	errs   chan error
}

// Success approves the Request with an interface, the interface
// MUST be able to be converted to a net.Conn(CONNECT) or a
// net.PacketConn(ASSOCIATE).
func (req *Request) Success(i interface{}) {
	if i == nil {
		req.Fail(nil)
	}

	switch req.cmd {
	case CONNECT:
		conn, ok := i.(net.Conn)
		if ok {
			req.connect(conn)
		} else {
			// r.Fail(errors.Errorf("CONNECT got %T rather than net.Conn .", i))
		}
	case ASSOCIATE:
		pl, ok := i.(net.PacketConn)
		if ok {
			req.pconn <- pl
		} else {
			// r.Fail(errors.Errorf("ASSOCIATE got %T rather than net.PacketConn .", i))
		}
	default:
		// r.Fail(errors.New("CMD(" + strconv.Itoa(int(r.CMD)) + ") unsupported."))
	}
}

// Fail denies the Request with a given error, the server will write a response
// of NormalFail message to the client, then close the connection.
func (req *Request) Fail(e error) {
	// r.logger.Log(INFO, "Connection from %v failed because %v.", r.ClientAddr(), e)

	resp := genCMDResp(req.clt.LocalAddr())
	resp[1] = FAIL
	_, _ = req.clt.Write(resp)

	//close(r.udpAck)
	req.cancel()
}

// DST returns a string which represents destination.
func (req *Request) DST() string {
	switch req.atyp {
	case DOMAIN:
		return string(req.dstAddr)
	default:
		return (net.IP(req.dstAddr)).String()
	}
}

// DSTPort returns destination port.
func (req *Request) DSTPort() int {
	return int(req.dstPort)
}

// CMD returns a byte which represents CMD type.
func (req *Request) CMD() byte {
	return req.cmd
}

func (req *Request) watch() {
	go func() {
		<-req.ctx.Done()
		_ = req.clt.Close()
	}()
}

func genCMDResp(iaddr net.Addr) []byte {
	resp := []byte{VERSION, SUCC, RSV, RSV}

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
		resp[3] = IPV4T
		resp = append(resp, laddr.To4()...)
	} else {
		// laddr is an IPv6 address.
		resp[3] = IPV6T
		resp = append(resp, laddr.To16()...)
	}
	resp = append(resp, byte(port>>8), byte(port&0xff))

	return resp
}
