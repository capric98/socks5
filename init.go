package socks5

import (
	"context"
	"time"

	"github.com/pkg/errors"
)

func (s *Server) init() error {
	if s.Logger == nil {
		s.Logger = DefaultLogger{}
	}
	if s.Port == 0 {
		return errors.New(FTALLOG + " Port cannot be 0!")
	}
	if s.Auth && s.Ident == nil {
		s.Logger.Println(WARNLOG, "Use Username&Password Authentication, but given Ident is nil.")
		s.Ident = make(map[string]string)
	}
	if s.TimeOut == 0 {
		s.TimeOut = time.Minute
	}

	s.ctx, s.stop = context.WithCancel(context.Background())
	s.req = make(chan *Request, 65535)
	return nil
}
