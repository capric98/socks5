package main

import (
	"log"
	"net"
	"strconv"
	"time"

	"github.com/capric98/socks5"
)

func main() {
	listen("tcp", "127.0.0.1")
	//listen("tcp", "[::1]")
	//listen("")
}

func listen(nt string, addr string) {
	// id := make(map[string]string)
	// id["username"] = "password!"
	s := &socks5.Server{
		Addr:   addr,
		Port:   9595,
		Logger: socks5.DefaultLogger{},
		// Ident:  id,
		// Auth:   true,
		AllowUDP: true,
	}
	if e := s.Listen(); e != nil {
		log.Fatal(e)
	}
	for {
		req := s.Accept()

		if req.CMD == socks5.ASSOCIATE {
			pl, e := net.ListenPacket("udp", ":")
			if e != nil {
				log.Fatal(e)
			}
			req.SuccessUDP(pl)
			continue
		}

		// Test SuccessUDP CONNECT rather than Success
		// pl, _ := net.ListenPacket("udp", ":")
		// req.SuccessUDP(pl)
		// continue

		var DST string
		if req.ATYP == 3 {
			DST = string(req.DST_ADDR)
			log.Println(req.CMD, string(req.DST_ADDR), req.DST_PORT)
		} else {
			log.Println(req.CMD, req.DST_ADDR, req.DST_PORT)
			DST = (net.IP(req.DST_ADDR)).String()
		}

		// Test Success ASSOCIATE rather than SuccessUDP
		// if DST == "" || DST == "0.0.0.0" {
		// 	DST = "www.baidu.com"
		// }
		// if req.DST_PORT == 0 {
		// 	req.DST_PORT = 443
		// }

		go func() {
			now := time.Now()
			conn, err := net.DialTimeout("tcp", DST+":"+strconv.Itoa(int(req.DST_PORT)), 10*time.Second)
			log.Println("Dial cost", time.Since(now).String())

			if err != nil {
				req.Fail(err)
			} else {
				req.Success(conn)
			}
		}()
	}
}
