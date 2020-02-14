package socks5

import (
	"fmt"
	"testing"
)

func TestType(t *testing.T) {
	fmt.Println(CONNECT, BIND, ASSOCIATE)
	t.Fail()
}

func BenchmarkChan(b *testing.B) {
	c := make(chan struct{}, 2)
	for i := 0; i < b.N; i++ {
		c <- struct{}{}
		<-c
	}
}
