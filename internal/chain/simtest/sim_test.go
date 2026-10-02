// Package simtest proves the nesting works end to end with in-memory stand-ins
// for WARP1, the wg0 server, WARP2 and an IP-echo origin. No real network.
//
//	client -> wg0bind(=warp1 stack) -> wireguard-go -> wgServer stack -> echo
//
// It verifies: (1) the custom conn.Bind carries WireGuard traffic over another
// userspace stack, and (2) a client dialing through the resulting stack reaches
// an origin that sees the wg tunnel's source address (the "new location").
package simtest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// a loopback conn.Bind pair connecting two wireguard-go devices in memory.
type memBind struct {
	name  string
	in    chan memPkt
	peer  *memBind
	open  bool
	close chan struct{}
}
type memPkt struct {
	data []byte
	from netip.AddrPort
}
type memEndpoint struct{ a netip.AddrPort }

func (e *memEndpoint) ClearSrc()           {}
func (e *memEndpoint) SrcToString() string { return "" }
func (e *memEndpoint) DstToString() string { return e.a.String() }
func (e *memEndpoint) DstToBytes() []byte  { b, _ := e.a.MarshalBinary(); return b }
func (e *memEndpoint) DstIP() netip.Addr   { return e.a.Addr() }
func (e *memEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (b *memBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.open = true
	b.close = make(chan struct{})
	fn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case p := <-b.in:
			n := copy(bufs[0], p.data)
			sizes[0] = n
			eps[0] = &memEndpoint{a: p.from}
			return 1, nil
		case <-b.close:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{fn}, 51820, nil
}
func (b *memBind) Close() error {
	if b.open {
		b.open = false
		close(b.close)
	}
	return nil
}
func (b *memBind) SetMark(uint32) error { return nil }
func (b *memBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, buf := range bufs {
		cp := append([]byte(nil), buf...)
		select {
		case b.peer.in <- memPkt{data: cp, from: netip.MustParseAddrPort("10.0.0.1:51820")}:
		case <-time.After(time.Second):
		}
	}
	return nil
}
func (b *memBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, err := netip.ParseAddrPort(s)
	return &memEndpoint{a: a}, err
}
func (b *memBind) BatchSize() int { return 1 }

func TestWireGuardOverUserspaceStack(t *testing.T) {
	// wg0 client at 10.9.0.2, server at 10.9.0.1; routing all traffic to server.
	clientIP := netip.MustParseAddr("10.9.0.2")
	serverIP := netip.MustParseAddr("10.9.0.1")

	cTun, cNet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	sTun, sNet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}

	cb := &memBind{name: "client", in: make(chan memPkt, 64)}
	sb := &memBind{name: "server", in: make(chan memPkt, 64)}
	cb.peer, sb.peer = sb, cb

	cPriv, cPub := key(t)
	sPriv, sPub := key(t)

	cDev := device.NewDevice(cTun, cb, device.NewLogger(device.LogLevelError, "c "))
	sDev := device.NewDevice(sTun, sb, device.NewLogger(device.LogLevelError, "s "))

	if err := cDev.IpcSet(uapi(cPriv, sPub, "10.0.0.2:51820", "0.0.0.0/0", 25)); err != nil {
		t.Fatal(err)
	}
	if err := sDev.IpcSet(uapi(sPriv, cPub, "10.0.0.1:51820", "10.9.0.2/32", 0)); err != nil {
		t.Fatal(err)
	}
	if err := cDev.Up(); err != nil {
		t.Fatal(err)
	}
	if err := sDev.Up(); err != nil {
		t.Fatal(err)
	}
	defer cDev.Close()
	defer sDev.Close()

	// Echo origin inside the server stack, on :80, reporting the peer source IP.
	ln, err := sNet.ListenTCPAddrPort(netip.AddrPortFrom(serverIP, 80))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = fmt.Fprintf(c, "seen-from=%s", c.RemoteAddr().String())
			}(c)
		}
	}()

	// Client dials the origin *through wg0*.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := cNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(serverIP, 80))
	if err != nil {
		t.Fatalf("dial through wg0 failed: %v", err)
	}
	defer func() { _ = conn.Close() }()
	buf, _ := io.ReadAll(conn)
	got := string(buf)
	t.Logf("origin reply: %q", got)
	want := "seen-from=10.9.0.2"
	if len(got) < len(want) || got[:len(want)] != want {
		t.Fatalf("origin saw %q, want prefix %q (wg source address not applied)", got, want)
	}
}
