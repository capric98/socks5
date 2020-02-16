package main

import (
	"log"
	"net"
	"strconv"
	"time"

	"github.com/capric98/socks5"
)

func main() {
	s := &socks5.Server{
		Addr:   "127.0.0.1",
		Port:   1080,
		Logger: socks5.DefaultNoLogger{},
		// For verbose running, use socks5.DefaultLogger{} instead.
		// You could also implement your Logger interface if you like :)
	}

	// If you would like to require an authentication:
	//
	// id := make(map[string]string)
	// id["username"] = "password!"
	// ...
	// s.Auth = true
	// s.Ident = id

	// If you would like to accept UDP replying:
	//
	s.AllowUDP = true
	// (optional) s.RewriteBND = YourPublicIP

	if e := s.Listen(); e != nil {
		log.Fatal(e)
	}
	// To stop the server: s.Shutdown()

	var DST string
	for {
		req := s.Accept()

		if req.ATYP == socks5.ATYPDOMAIN {
			DST = string(req.DST_ADDR)
		} else {
			DST = (net.IP(req.DST_ADDR)).String()
		}

		switch req.CMD {
		case socks5.CONNECT:
			log.Println("CONNECT:", req.CltAddr(), "->", DST+":"+strconv.Itoa(int(req.DST_PORT)))
			now := time.Now()
			conn, err := net.DialTimeout("tcp", DST+":"+strconv.Itoa(int(req.DST_PORT)), 10*time.Second)
			log.Println("Dial to", DST+":"+strconv.Itoa(int(req.DST_PORT)), "in", time.Since(now).String())
			if err != nil {
				req.Fail(err)
			} else {
				req.Success(conn)
			}
		case socks5.ASSOCIATE:
			log.Println("ASSOCIATE:", req.CltAddr(), "->", DST+":"+strconv.Itoa(int(req.DST_PORT)))
			pl, e := net.ListenPacket("udp", ":")
			if e != nil {
				req.FailUDP(e)
			}
			req.SuccessUDP(pl)
		default:
			continue
		}
	}
}