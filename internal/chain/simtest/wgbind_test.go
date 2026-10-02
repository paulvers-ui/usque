package simtest

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/internal/chain"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// wirePkt is one UDP datagram seen on the wire between WARP1's stack and the
// wg0 server.
type wirePkt struct {
	b    []byte
	from netip.AddrPort
}

// wireBind is the wg0 *server's* bind. It stands in for the internet behind
// WARP1: it reads the raw IPv4 packets WARP1's stack emits, hands the UDP
// payloads addressed to self to the server, and wraps the server's replies
// back into IPv4/UDP packets for the stack. No netstack socket semantics are
// involved on this side, so the test isolates chain.NewNetstackBind.
type wireBind struct {
	dev  tun.Device
	self netip.AddrPort
	in   chan wirePkt
}

func newWireBind(dev tun.Device, self netip.AddrPort) *wireBind {
	w := &wireBind{dev: dev, self: self, in: make(chan wirePkt, 256)}
	go w.pump()
	return w
}

func (w *wireBind) pump() {
	bufs := [][]byte{make([]byte, 65535)}
	sizes := []int{0}
	for {
		n, err := w.dev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			p := bufs[i][:sizes[i]]
			if len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 {
				continue
			}
			ihl := int(p[0]&0x0f) * 4
			if len(p) < ihl+8 {
				continue
			}
			u := p[ihl:]
			dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[16:20])), binary.BigEndian.Uint16(u[2:4]))
			if dst != w.self {
				continue
			}
			ulen := int(binary.BigEndian.Uint16(u[4:6]))
			if ulen < 8 || ulen > len(u) {
				continue
			}
			src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[12:16])), binary.BigEndian.Uint16(u[0:2]))
			w.in <- wirePkt{b: append([]byte(nil), u[8:ulen]...), from: src}
		}
	}
}

func (w *wireBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	fn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		p, ok := <-w.in
		if !ok {
			return 0, net.ErrClosed
		}
		sizes[0] = copy(bufs[0], p.b)
		eps[0] = &memEndpoint{a: p.from}
		return 1, nil
	}
	return []conn.ReceiveFunc{fn}, w.self.Port(), nil
}

// Close is a no-op: wireguard-go closes the bind before every Open.
func (w *wireBind) Close() error         { return nil }
func (w *wireBind) SetMark(uint32) error { return nil }
func (w *wireBind) BatchSize() int       { return 1 }

func (w *wireBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst := ep.(*memEndpoint).a
	for _, payload := range bufs {
		p := make([]byte, 28+len(payload))
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		binary.BigEndian.PutUint16(p[6:8], 0x4000) // DF
		p[8] = 64
		p[9] = 17
		src4, dst4 := w.self.Addr().As4(), dst.Addr().As4()
		copy(p[12:16], src4[:])
		copy(p[16:20], dst4[:])
		binary.BigEndian.PutUint16(p[10:12], ipv4Checksum(p[:20]))
		binary.BigEndian.PutUint16(p[20:22], w.self.Port())
		binary.BigEndian.PutUint16(p[22:24], dst.Port())
		binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
		// UDP checksum 0 = none, allowed for IPv4.
		copy(p[28:], payload)
		if _, err := w.dev.Write([][]byte{p}, 0); err != nil {
			return err
		}
	}
	return nil
}

func (w *wireBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &memEndpoint{a: ap}, nil
}

func ipv4Checksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// TestWireGuardOverNetstackBind runs wg0 exactly as `usque chain` does: its
// UDP goes through chain.NewNetstackBind on WARP1's userspace stack. Before
// the connected-UDP fix every handshake failed on a real phone with
// "write udp 0.0.0.0:N->server:51820: network is unreachable".
func TestWireGuardOverNetstackBind(t *testing.T) {
	// WARP1's stack (the underlay wg0 rides on).
	warp1IP := netip.MustParseAddr("172.16.0.2")
	underTun, underNet, err := netstack.CreateNetTUN([]netip.Addr{warp1IP}, nil, 1280)
	must(t, err)

	// wg0 server, reachable at a public address behind WARP1.
	serverEP := netip.MustParseAddrPort("195.51.100.1:51820")
	clientIP := netip.MustParseAddr("10.9.0.2")
	serverIP := netip.MustParseAddr("10.9.0.1")
	cTun, cNet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, chain.WGMTU(1280, false, 0))
	must(t, err)
	sTun, sNet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	must(t, err)

	cPriv, cPub := key(t)
	sPriv, sPub := key(t)
	cDev := device.NewDevice(cTun, chain.NewNetstackBind(underNet), device.NewLogger(device.LogLevelError, "wg0 "))
	sDev := device.NewDevice(sTun, newWireBind(underTun, serverEP), device.NewLogger(device.LogLevelError, "srv "))
	defer cDev.Close()
	defer sDev.Close()

	must(t, cDev.IpcSet(uapi(cPriv, sPub, serverEP.String(), "0.0.0.0/0", 0)))
	// The server has no endpoint for the client; it learns it from the handshake.
	must(t, sDev.IpcSet(fmt.Sprintf("private_key=%x\npublic_key=%x\nallowed_ip=%s/32\n", sPriv[:], cPub[:], clientIP)))
	must(t, cDev.Up())
	must(t, sDev.Up())

	ln, err := sNet.ListenTCPAddrPort(netip.AddrPortFrom(serverIP, 80))
	must(t, err)
	go echoSrc(ln)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := cNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(serverIP, 80))
	if err != nil {
		t.Fatalf("dial through wg0-over-netstack failed: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	b, _ := io.ReadAll(c)
	if got := string(b); !has(got, "seen-from=10.9.0.2") {
		t.Fatalf("origin saw %q, want seen-from=10.9.0.2", got)
	}

	// The server must have learned the client at WARP1's address: the wg0
	// packets really left through the underlay stack.
	s, err := sDev.IpcGet()
	must(t, err)
	if !strings.Contains(s, "endpoint="+warp1IP.String()+":") {
		t.Fatalf("server did not see the client at %s:\n%s", warp1IP, s)
	}
	t.Logf("wg0 over netstack ok; server sees client via WARP1 at %s", warp1IP)
}
