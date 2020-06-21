package auth

import "net"

type noauth struct{}

// NewNoAuth news an authenticator with no auth.
func NewNoAuth() Authenticator {
	return &noauth{}
}

func (n *noauth) Method() byte {
	return 0 // 0 -> No Auth
}

func (n *noauth) Check(conn net.Conn) bool {
	return true
}
