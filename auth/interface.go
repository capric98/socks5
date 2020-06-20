package auth

import "net"

// Authenticator ...
type Authenticator interface {
	Method() byte
	Check(conn net.Conn) bool
}
