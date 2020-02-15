package main

import (
	"log"
	"net"
	"strconv"
	"time"

	"github.com/capric98/socks5"
)

func main() {
	// m := make(map[string]string)
	// m["test"] = "abc"
	s := &socks5.Server{
		Addr:   "127.0.0.1",
		Port:   9595,
		Logger: socks5.DefaultLogger{},
		// Ident:  m,
		// Auth:   true,
	}
	if e := s.Listen(); e != nil {
		log.Fatal(e)
	}
	for {
		req := s.Accept()

		var DST string
		if req.ATYP == 3 {
			DST = string(req.DST_ADDR)
			log.Println(req.CMD, string(req.DST_ADDR), req.DST_PORT)
		} else {
			log.Println(req.CMD, req.DST_ADDR, req.DST_PORT)
			DST = (net.IP(req.DST_ADDR)).String()
		}

		go func() {
			now := time.Now()
			conn, err := net.DialTimeout(s.NetType, DST+":"+strconv.Itoa(int(req.DST_PORT)), 10*time.Second)
			log.Println("Dial cost", time.Since(now).String())

			if err != nil {
				req.Fail(err)
			} else {
				req.Success(conn)
			}
		}()
	}
}
