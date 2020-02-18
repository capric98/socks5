# socks5

**A simple socks5 server written in Go.**

## Features
* CMD
  * - [x] CONNECT
  * - [ ] BIND
  * - [x] ASSOCIATE
* Identifier/Method
  * - [x] No Auth
  * - [ ] GSSAPI
  * - [x] Username/Password
  * - [ ] IANA Assigned
  * - [ ] Reservered for Private Methods
  * - [x] No Accept : )
* Miscellaneous
  * - [ ] REASSEMBLY QUEUE / REASSEMBLY TIMER

## Usage
* New a `Server`
  * `Addr`: Server will listen this address.
  * `Port`: Server will bind to this port.
  * `AllowUDP`: If this was set to `false`, you would only get `CONNECT` requests from `(*Server).Accept()`
  * `RewriteBND`: See [here](https://github.com/capric98/socks5/blob/master/type.go#L83).
  * `Auth`: If this was set to `true`, the Server would force clients to use Username and Password to proof their identities.
  * `Ident`: A `map[string]string` which stores Username and Password pairs.
  * `Logger`: An `interface{}` which implements `Log()`.
  * `TimeOut`: The connection to the Server will timeout if its `*Request` fails to `Success` or `Fail` in `TimeOut` time.
* `(*Server).Listen()`
* Keep `(*Server).Accept()`, and handle every `*Request`:
  * By default, you need to implement an interface which could be converted to `net.Conn`.
  * If you'd like to handle ASSOCIATE (UDP relying) requests, you need to implement an interface which could be converted to `net.PacketConn`.
  * Use `(*Request).Success()` or `(*Request).Fail()` to handle a `*Request`.

## Example
This is a very simple example which uses default `net.Conn` and `net.PacketConn` to handle `*Request`. Please notice that in this example, ASSOCIATE requests will be refused since `s.AllowUDP` has a default `false` value and `s.AllowUDP = true` is commented.
```golang
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
		Addr: "127.0.0.1",
		Port: 1080,
		// For silent running, use socks5.NoLogger{}.
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
	// s.AllowUDP = true
	//
	// Read this to know in what situation you'd
	// like to appoint RewriteBND:
	// https://github.com/capric98/socks5/blob/master/type.go#L83
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
				req.Fail(e)
			} else {
				req.Success(pl)
			}
		default:
			continue
		}
	}
}
```

### LESS IS MORE