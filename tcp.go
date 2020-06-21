package socks5

import (
	"io"
	"net"
	"time"
)

func (req *Request) connect(conn net.Conn) {
	resp := genCMDResp(req.clt.LocalAddr())
	if _, e := req.clt.Write(resp); e != nil {
		req.cancel()
		req.errs <- e
		return
	}
	// Cancel Deadline
	_ = req.clt.SetDeadline(time.Time{})

	// Pipe Connection
	go func() {
		defer conn.Close()
		defer req.cancel()

		_, e := io.Copy(conn, req.clt)
		if e != nil {
			select {
			case <-req.ctx.Done():
				return
			default:
				req.errs <- e
			}
		}
	}()
	go func() {
		defer conn.Close()
		defer req.cancel()

		_, e := io.Copy(req.clt, conn)
		if e != nil {
			select {
			case <-req.ctx.Done():
				return
			default:
				req.errs <- e
			}
		}
	}()
}
