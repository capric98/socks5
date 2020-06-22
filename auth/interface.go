package auth

import "net"

// Authenticator is an interface of auth methods.
type Authenticator interface {
	Method() byte
	Check(conn net.Conn) bool
}
