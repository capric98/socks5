package socks5

import (
	"context"
	"sync"
	"time"
)

func (s *Server) init() {
	if s.Auth && s.Ident == nil {
		s.Ident = make(map[string]string)
	}
	if s.TimeOut == 0 {
		s.TimeOut = time.Minute
	}

	s.ctx, s.stop = context.WithCancel(context.Background())
	s.mu = sync.Mutex{}
	s.req = make(chan *Request, 65535)
}
