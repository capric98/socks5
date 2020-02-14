package socks5

import (
	"context"
	"sync"

	"github.com/panjf2000/gnet"
)

func (s *Server) init() {
	if s.NetType == "" {
		s.NetType = "tcp"
	}
	if s.MaxQueueLen <= 0 {
		s.MaxQueueLen = 1200
	}

	s.ctx = context.Background()
	s.mu = sync.Mutex{}
	s.rMap = make(map[gnet.Conn]*Request)
	s.req = make(chan *Request, 65535)
}
