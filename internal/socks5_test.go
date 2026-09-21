package internal

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/txthinking/socks5"
)

func plainDial(network, _, raddr string) (net.Conn, error) {
	return net.Dial(network, raddr)
}

// freeLoopbackAddr returns a 127.0.0.1 port free for both TCP and UDP: the server
// listens on the same port for its TCP control connections and its UDP relay.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	for range 20 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		_ = l.Close()
		if pc, err := net.ListenPacket("udp", addr); err == nil {
			_ = pc.Close()
			return addr
		}
	}
	t.Fatal("no loopback port free for both TCP and UDP")
	return ""
}

func startTestSOCKS5(t *testing.T) string {
	t.Helper()
	addr := freeLoopbackAddr(t)
	s, err := NewSOCKS5Server(SOCKS5Config{
		Addr: addr,
		DialTCP: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("CONNECT is not used by this test")
		},
		UDPTimeout: 5 * time.Second,
		Logger:     log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The relay normally reaches targets through the tunnel; here it dials them directly.
	prev := socks5.DialUDP
	socks5.DialUDP = plainDial
	t.Cleanup(func() {
		socks5.DialUDP = prev
		_ = s.server.Shutdown()
	})
	go func() { _ = s.Start() }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("SOCKS5 server did not start on %s", addr)
	return ""
}

func TestPortlessAssociationsLifetime(t *testing.T) {
	var p portlessAssociations
	release1 := p.add("127.0.0.1")
	release2 := p.add("127.0.0.1")
	done, ok := p.get("127.0.0.1")
	if !ok {
		t.Fatal("association not found")
	}
	if _, ok := p.get("10.0.0.1"); ok {
		t.Fatal("unrelated IP is associated")
	}

	release1()
	if _, ok := p.get("127.0.0.1"); !ok {
		t.Fatal("association ended while another one for the IP is still open")
	}
	select {
	case <-done:
		t.Fatal("done closed early")
	default:
	}

	release2()
	if _, ok := p.get("127.0.0.1"); ok {
		t.Fatal("association outlived its last TCP control connection")
	}
	select {
	case <-done:
	default:
		t.Fatal("done not closed after the last association ended")
	}
}

// TestUDPAssociateWithoutClientPort mirrors firestack's SOCKS5 client: it sends UDP
// ASSOCIATE with DST.ADDR/DST.PORT 0.0.0.0:0 and then sends its datagrams from a fresh
// ephemeral port, not the port of its TCP control connection. RFC 1928 §7 only
// requires those datagrams to come from the client's IP.
func TestUDPAssociateWithoutClientPort(t *testing.T) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buf[:n], from)
		}
	}()

	proxy := startTestSOCKS5(t)
	client, err := socks5.NewClient(proxy, "", "", 5, 5)
	if err != nil {
		t.Fatal(err)
	}
	client.DialTCP = plainDial
	client.DialUDP = plainDial // an ephemeral source port, as firestack does
	conn, err := client.Dial("udp", echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// A few tries in case the first datagram beats the relay's UDP listener.
	buf := make([]byte, 64)
	start := time.Now()
	for try := range 3 {
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buf)
		if err == nil {
			if got := string(buf[:n]); got != "ping" {
				t.Fatalf("got %q, want %q", got, "ping")
			}
			t.Logf("echo on try %d after %v", try+1, time.Since(start))
			return
		}
		if try == 2 {
			t.Fatalf("no reply through the SOCKS5 UDP relay: %v", err)
		}
	}
}
