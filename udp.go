package socks5

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	bufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 65535)
			return &buf
		},
	}
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

	plLocal, e := net.ListenPacket("udp", s.addr[:strings.Index(s.addr, ":")+1])
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
	// This goroutine will return if the connection was closed.
	go func() {
		var eof error
		one := make([]byte, 1)
		for ; eof == nil; _, eof = conn.Read(one) {
		}

		// The life cycle of the ASSOCIATE should be controled
		// by its original TCP connection.
		plRemote.SetDeadline(time.Now())
		plLocal.SetDeadline(time.Now())
		req.cancel()
	}()

	addrChan := make(chan net.Addr, 32)
	defer close(addrChan)

	go func() {
		defer func() { _ = recover() }()

		var n int
		var re, we error
		var taddr, srcaddr net.Addr
		buffer := *(bufPool.Get().(*[]byte))
		defer func() {
			bufPool.Put(&buffer)
		}()

		// Get first toAddr.
		select {
		case taddr = <-addrChan:
		case <-req.ctx.Done():
			return
		}

		var head []byte
		// headLen := len(head)

		for re == nil && we == nil {
			n, srcaddr, re = plRemote.ReadFrom(buffer)
			if n == 0 {
				continue
			}
			if _, ok := srcaddr.(*net.UDPAddr); !ok {
				continue
			}
			srcip, srcport := srcaddr.(*net.UDPAddr).IP, srcaddr.(*net.UDPAddr).Port
			switch srcip.To4() {
			case nil:
				// src IPv6
				head = append(head, []byte{0, 0, 0, IPV6T}...)
				head = append(head, []byte(srcip)...)
			default:
				// src IPv4
				head = append(head, []byte{0, 0, 0, IPV4T}...)
				head = append(head, []byte(srcip.To4())...)
			}
			head = append(head, byte(srcport>>8), byte(srcport))

			// append payload data
			head = append(head, buffer[:n]...)

			select {
			case taddr = <-addrChan:
				if taddr == nil {
					return
				}
			default:
			}
			_, we = plLocal.WriteTo(head, taddr)
			head = head[:0]
		}
	}()

	var n, domainEnd int
	var re, we error
	var caddr, raddr net.Addr
	buffer := *(bufPool.Get().(*[]byte))
	defer func() {
		bufPool.Put(&buffer)
	}()

	for we == nil && re == nil {
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
