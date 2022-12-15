package main

import (
	"flag"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	// "net/http"
	// _ "net/http/pprof"

	"github.com/capric98/socks5"
	"github.com/capric98/socks5/auth"
)

var (
	addr       string
	allowUDP   bool
	rewriteBND string
)

func init() {
	flag.StringVar(&addr, "addr", "127.0.0.1:1080", "listen address")
	flag.StringVar(&rewriteBND, "rbnd", "", "UDP rewrite address")
	flag.BoolVar(&allowUDP, "udp", false, "allow udp proxy")
	flag.Parse()

	if rewriteBND == "" {
		rewriteBND = strings.Split(addr, ":")[0]
	}
}

func main() {
	// go func() {
	// 	log.Println(http.ListenAndServe("127.0.0.1:6060", nil))
	// }()

	errs := make(chan error)
	srv := socks5.NewServer(addr, &socks5.SOpts{
		AllowUDP:   true,
		RewriteBND: net.ParseIP(addr),
		Timeout:    10 * time.Second,
		ErrChan:    errs,
	})
	srv.SetAuth(auth.NewNoAuth())
	srv.SetAuth(auth.NewUaP())
	srv.GetAuth(socks5.UAP).(*auth.Uap).Add("a", "b")
	if e := srv.Listen(); e != nil {
		log.Fatal(e)
	}

	go func() {
		for e := range errs {
			log.Println(e)
		}
	}()

	var DST string
	for {
		if req := srv.Accept(); req != nil {
			go func(req *socks5.Request) {
				DST = req.DST()
				switch req.CMD() {
				case socks5.CONNECT:
					now := time.Now()
					conn, err := net.DialTimeout("tcp", DST+":"+strconv.Itoa(req.DSTPort()), 30*time.Second)
					log.Println("Dial to", DST+":"+strconv.Itoa(req.DSTPort()), "in", time.Since(now).String())
					if err != nil {
						req.Fail(err)
					} else {
						req.Success(conn)
					}
				case socks5.ASSOCIATE:
					pl, e := net.ListenPacket("udp", ":")
					if e != nil {
						req.Fail(e)
					} else {
						req.Success(pl)
					}
				}
			}(req)
		}
	}
}
