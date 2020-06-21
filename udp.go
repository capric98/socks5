package socks5

import (
	"net"
	"strconv"
	"time"
)

func (s *Server) associate(req *Request) {
	defer func() { _ = recover() }()
	defer req.cancel()

	conn := req.clt
	plRemote := <-req.pconn
	if plRemote == nil {
		return
	}
	defer plRemote.Close()

	// Cancel Deadline
	_ = req.clt.SetDeadline(time.Time{})

	plLocal, e := net.ListenPacket("udp", s.addr+":")
	if e != nil {
		_, _ = conn.Write([]byte{VERSION, FAIL, RSV, IPV4T, 0, 0, 0, 0, 0, 0})
		return
	}
	defer plLocal.Close()

	laddr := plLocal.LocalAddr()
	if s.rewriteBND != nil {
		// Rewrite Bind Addr
		laddr = net.Addr(&net.UDPAddr{
			IP:   s.rewriteBND,
			Port: laddr.(*net.UDPAddr).Port,
		})
	}
	cmdResp := genCMDResp(laddr)
	if _, e := conn.Write(cmdResp); e != nil {
		return
	}

	// Detect conn close.
	// This goroutine will return if req.watch() closes the connection.
	go func() {
		var eof error
		one := make([]byte, 1)
		for ; eof == nil; _, eof = conn.Read(one) {
		}
		req.cancel()
	}()

	addrChan := make(chan net.Addr, 32)
	defer close(addrChan)

	go func() {
		defer func() { _ = recover() }()

		var n int
		var re, we error
		var taddr net.Addr
		buffer := make([]byte, 65535)

		// Get first toAddr.
		select {
		case taddr = <-addrChan:
		case <-req.ctx.Done():
			return
		}

		head := append([]byte{0, 0, 0}, cmdResp[3:]...)
		headLen := len(head)

		for re == nil && we == nil {
			// The life cycle of the ASSOCIATE should be controled
			// by its original TCP connection.
			// _ = plLocal.SetReadDeadline(time.Now().Add(s.TimeOut))
			// _ = plRemote.SetWriteDeadline(time.Now().Add(s.TimeOut))
			n, _, re = plRemote.ReadFrom(buffer)
			if n == 0 {
				continue
			}

			head = append(head, buffer[:n]...)
			select {
			case taddr = <-addrChan:
				if taddr == nil {
					if taddr == nil {
						return
					}
				}
			default:
			}
			_, we = plLocal.WriteTo(head, taddr)
			head = head[:headLen]
		}
	}()

	var n, domainEnd int
	var re, we error
	var caddr, raddr net.Addr
	buffer := make([]byte, 65535)
	for we == nil && re == nil {
		// The life cycle of the ASSOCIATE should be controled
		// by its original TCP connection.
		// _ = plLocal.SetReadDeadline(time.Now().Add(s.TimeOut))
		// _ = plRemote.SetWriteDeadline(time.Now().Add(s.TimeOut))
		n, caddr, re = plLocal.ReadFrom(buffer)
		if n == 0 {
			continue
		}
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
		case IPV4T:
			_, we = plRemote.WriteTo(buffer[10:n], &net.UDPAddr{
				IP:   net.IP(buffer[4:8]),
				Port: int(buffer[8])<<8 + int(buffer[9]),
			})
		case IPV6T:
			_, we = plRemote.WriteTo(buffer[22:n], &net.UDPAddr{
				IP:   net.IP(buffer[4:20]),
				Port: int(buffer[20])<<8 + int(buffer[21]),
			})
		case DOMAIN:
			domainEnd = 5 + int(buffer[4])
			raddr, _ = net.ResolveUDPAddr("udp", string(buffer[5:domainEnd])+":"+strconv.Itoa(int(buffer[domainEnd])<<8+int(buffer[domainEnd+1])))
			_, we = plRemote.WriteTo(buffer[domainEnd+2:n], raddr)
		}
	}
}
