package socks5

import (
	"io"
	"net"
)

func (r *Request) pipe(s net.Conn) {
	c := r.conn
	// c -> s
	go func() {
		var tmp, n int
		var e error
		for {
			for {
				tmp = c.q.head
				if tmp == c.q.tail {
					break
				}
				if len(c.q.ring[tmp]) != 0 {
					n, e = s.Write(c.q.ring[tmp])
					if e != nil {
						r.Error(e)
					}
					if n != len(c.q.ring[tmp]) {
						r.Error(io.ErrShortWrite)
					}
				}
				c.q.ring[tmp] = (c.q.ring[tmp])[:0]
				c.q.head++
				if c.q.head == c.q.maxLen {
					c.q.head = 0
				}
			}

			select {
			case <-c.wake:
			case <-c.ctx.Done():
				return
			}
		}
	}()

	// s -> c
	go func() {
		_, _ = io.Copy(c, s)
	}()
}

func (s *sConn) Write(b []byte) (n int, e error) {
	n = len(b)

	// TODO: use a ring buffer to reduce overhead.
	s.c.AsyncWrite(append([]byte{}, b...))
	s.c.Wake()
	// go func() {
	// 	time.Sleep(time.Second)
	// 	runtime.KeepAlive(b)
	// }()
	return
}
