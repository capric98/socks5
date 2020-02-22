package socks5

import (
	"net"
)

func (s *Server) psswdauth(conn net.Conn) (bool, []byte) {
	head := make([]byte, 2)
	resp := []byte{1, 1}
	if n, e := conn.Read(head); n != 2 || e != nil || head[0] != 1 {
		return false, resp
	}
	userbyte := make([]byte, int(head[1])+1)
	if n, e := conn.Read(userbyte); n != int(head[1])+1 || e != nil {
		return false, resp
	}
	password := make([]byte, int(userbyte[int(head[1])]))
	if n, e := conn.Read(password); n != int(userbyte[int(head[1])]) || e != nil {
		return false, resp
	}

	if s.Ident[string(userbyte[:int(head[1])])] == string(password) {
		return true, []byte{1, 0}
	}
	return false, resp
}
