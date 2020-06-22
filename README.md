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
    * Example: `127.0.0.1:1080`
  * `Opts`: Server options.
    * `AllowUDP`: Server to accept `ASSOCIATE` CMD or not.
	* `RewriteBND`: See [here](https://github.com/capric98/socks5/blob/master/server.go#L34).
	* `Timeout`: Control timeout of a connection.
	* `ErrChan`: Handle errors by yourself or just ignore them(set to nil).
* `(*Server).Listen()`
* Keep `(*Server).Accept()`, and handle every non-nil `*Request`:
  * By default, you need to implement an interface which could be converted to `net.Conn`.
  * If you'd like to handle ASSOCIATE (UDP relying) requests, you need to implement an interface which could be converted to `net.PacketConn`.
  * Use `(*Request).Success()` or `(*Request).Fail()` to handle a `*Request`.

## Example
This is a very simple example which uses default `net.Conn` and `net.PacketConn` to handle `*Request`.

<details>
  <summary>Code</summary>

```golang
package main

import (
	"log"
	"net"
	"strconv"
	"time"

	"github.com/capric98/socks5"
	"github.com/capric98/socks5/auth"
)

func main() {
	errs := make(chan error)
	srv := socks5.NewServer("127.0.0.1:1080", &socks5.SOpts{
		AllowUDP:   true,
		RewriteBND: net.IPv4(127, 0, 0, 1),
		Timeout:    10 * time.Second,
		ErrChan:    errs,
	})

	// You could also implement your own Authenticator interface.
	srv.SetAuth(auth.NewNoAuth())
	// Do not set NoAuth to force User&Pass auth.
	srv.SetAuth(auth.NewUaP())
	// You could add or delete user at any time, but
	// be careful to set UAP first, or else you will
	// get panic.
	srv.GetAuth(socks5.UAP).(*auth.Uap).Add("Alice", "alice_password")
	if e := srv.Listen(); e != nil {
		log.Fatal(e)
	}

	go func() {
		for e := range errs {
			// handle errors blabla...
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
```

</details>

### LESS IS MORE
