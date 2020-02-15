package socks5

import (
	"context"
	"net"
	"time"
)

func (r *Request) Fail(e error) {
	r.cancel()
}

func (r *Request) Success(conn net.Conn) {
	r.srv = conn
	r.watch()
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
		r.cancel()
	}
	// Cancel Deadline
	_ = r.clt.SetDeadline(time.Time{})

	r.pipe()
}

func (r *Request) watch() {
	go func() {
		<-r.ctx.Done()
		r.logger.Println(INFOLOG, r.clt.RemoteAddr(), "connection done.")
		_ = r.clt.Close()
		_ = r.srv.Close()
	}()
}

func (r *Request) pipe() {
	// var arn, awn, brn, bwn int
	// var ae, be error
	// a := make([]byte, 16*1024)
	// b := make([]byte, 16*1024)

	// go func() {
	// 	for {
	// 		select {
	// 		case <-r.ctx.Done():
	// 			//r.logger.Println("A quit")
	// 			return
	// 		default:
	// 			arn, ae = r.srv.Read(a)
	// 			if ae != nil {
	// 				//r.logger.Println("A cancel")
	// 				r.cancel()
	// 			}
	// 			awn, ae = r.clt.Write(a[:arn])
	// 			if ae != nil || awn != arn {
	// 				//r.logger.Println("A cancel")
	// 				r.cancel()
	// 			}
	// 		}
	// 	}
	// }()

	// for {
	// 	select {
	// 	case <-r.ctx.Done():
	// 		//r.logger.Println("B quit")
	// 		return
	// 	default:
	// 		brn, be = r.clt.Read(b)
	// 		if be != nil {
	// 			//r.logger.Println("B cancel")
	// 			r.cancel()
	// 		}
	// 		bwn, be = r.srv.Write(b[:brn])
	// 		if be != nil || bwn != brn {
	// 			//r.logger.Println("B cancel")
	// 			r.cancel()
	// 		}
	// 	}
	// }
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
		for {
			select {
			case <-ctx.Done():
				return
			case rf = <-rc:
				rf.n, re = src.Read(rf.b)
				if re != nil {
					cancel()
				}
				wc <- rf
			}
		}
	}()

	defer func() {
		select {
		case wf = <-wc:
			_, _ = dst.Write(wf.b[:wf.n])
		default:
			return
		}
	}()
	for {
		select {
		case <-ctx.Done():
			//close(rc)
			return
		case wf = <-wc:
			wn, we = dst.Write(wf.b[:wf.n])
			if we != nil || wn != wf.n {
				cancel()
			}
			rc <- wf
		}
	}
}
