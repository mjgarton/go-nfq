// Copyright (C) 2015 Martin Garton <garton@gmail.com>
package nfq

import (
	"net"
	"testing"
	"time"
)

func TestNfq(t *testing.T) {

	gotpacket := make(chan struct{}, 16)

	cb := func(date []byte) Verdict {
		gotpacket <- struct{}{}
		return NF_ACCEPT
	}

	nfq, err := NewDefaultQueue(0, cb)
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.ListenPacket("udp", "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:9999")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	if _, err := l.WriteTo([]byte{1, 2, 3}, addr); err != nil {
		t.Fatal(err)
	}

	<-gotpacket

	select {
	case <-gotpacket:
		t.Fatal("didn't expect another packet")
	default:
	}

	nfq.Close()
}

func TestCloseWhenWritingLots(t *testing.T) {
	for i := 0; i < 100; i++ {
		testCloseWhenWritingLots(t)
	}
}

// This tries to trigger a race during close that's hopefully fixed now and
// previously triggered a SIGALRM in the C code.
func testCloseWhenWritingLots(t *testing.T) {

	cb := func(date []byte) Verdict {
		return NF_ACCEPT
	}

	nfq, err := NewDefaultQueue(0, cb)
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.ListenPacket("udp", "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:9999")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	closing := make(chan chan struct{})

	go func() {
		for {
			select {
			case closed := <-closing:
				close(closed)
				return
			default:
				if _, err := l.WriteTo([]byte{1, 2, 3}, addr); err != nil {
					t.Fatal(err)
				}
			}
		}
	}()

	time.Sleep(5 * time.Microsecond)
	nfq.Close()

	closed := make(chan struct{})
	closing <- closed
	<-closed

}
