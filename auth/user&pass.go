package auth

import (
	"net"
	"sync"
)

type uap struct {
	store *sync.Map
}

// NewUaP news an user&pass authenticator.
func NewUaP() Authenticator {
	return &uap{store: &sync.Map{}}
}

func (a *uap) Method() byte {
	return 1 // 1 -> Username & Password Auth
}

func (a *uap) Check(conn net.Conn) (passed bool) {
	defer func() {
		if passed {
			_, e := conn.Write([]byte{1, 0})
			if e != nil {
				passed = false
			}
		} else {
			_, _ = conn.Write([]byte{1, 1})
		}
	}()

	head := make([]byte, 2)
	if n, e := conn.Read(head); n != 2 || e != nil || head[0] != 1 {
		return false
	}
	userbyte := make([]byte, int(head[1])+1)
	if n, e := conn.Read(userbyte); n != int(head[1])+1 || e != nil {
		return false
	}
	password := make([]byte, int(userbyte[int(head[1])]))
	if n, e := conn.Read(password); n != int(userbyte[int(head[1])]) || e != nil {
		return false
	}

	si, ok := a.store.Load(string(userbyte[:int(head[1])]))
	if !ok || si == nil {
		return false
	}

	if si.(string) != string(password) {
		return false
	}

	return true
}

func (a *uap) Add(user, pass string) {
	a.store.Store(user, pass)
}

func (a *uap) Delete(user string) {
	a.store.Delete(user)
}
