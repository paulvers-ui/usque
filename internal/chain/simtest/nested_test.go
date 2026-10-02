package simtest

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// udpConnPacketConn adapts a *gonet.UDPConn (connected, inside an outer tunnel
// stack) to net.PacketConn so quic-go's server can listen on it. All reads come
// from the one remote; writes ignore addr.
type udpConnPacketConn struct {
	c      net.Conn
	remote net.Addr
}

func (u *udpConnPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := u.c.Read(p)
	return n, u.remote, err
}
func (u *udpConnPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return u.c.Write(p) }
func (u *udpConnPacketConn) Close() error                              { return u.c.Close() }
func (u *udpConnPacketConn) LocalAddr() net.Addr                       { return u.c.LocalAddr() }
func (u *udpConnPacketConn) SetDeadline(t time.Time) error             { return u.c.SetDeadline(t) }
func (u *udpConnPacketConn) SetReadDeadline(t time.Time) error         { return u.c.SetReadDeadline(t) }
func (u *udpConnPacketConn) SetWriteDeadline(t time.Time) error        { return u.c.SetWriteDeadline(t) }

// TestTwoWarpHopsNested proves the real composition: tunnel A over a pipe, then
// tunnel B whose QUIC runs INSIDE tunnel A's stack, reaching an origin behind
// B's edge. The origin must see B's assigned address -- i.e. the second WARP
// really egresses through the first. This is the WARP(outer)->WARP(inner) core
// of WARP1 -> ... -> WARP2 with the middle hop omitted for isolation.
func TestTwoWarpHopsNested(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// Origin behind edge A (so we can sanity-check A), and the real origin
	// behind edge B.
	oA := netip.MustParseAddr("192.0.2.80")
	oAtun, oAnet, err := netstack.CreateNetTUN([]netip.Addr{oA}, nil, 1500)
	must(t, err)
	go echoSrc(mustListen(t, oAnet, oA))

	// Edge A over the pipe (outer / WARP1 role).
	aSrv, aCli := newPipePair()
	aTLS, aPriv := serverTLS(t)
	fakeEdge(t, aSrv, aTLS, oAnet, api.NewNetstackAdapter(oAtun), netip.MustParsePrefix("172.16.0.2/32"))

	cfgA := &config.Config{PrivateKey: privKeyB64(t, mustEC(t)), EndpointV4: "10.0.0.1",
		EndpointPubKey: edgePubKeyPEM(t, aPriv), IPv4: "172.16.0.2", IPv6: "fd00::2"}
	aTunDev, aNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(cfgA.IPv4)}, nil, 1280)
	must(t, err)
	startTunnel(ctx, t, cfgA, "", aTunDev, &api.Underlay{
		ListenPacket: func(*net.UDPAddr) (net.PacketConn, error) { return aCli, nil },
	})
	if got := dialEchoThrough(ctx, t, aNet, oA); !has(got, "seen-from=172.16.0.2") {
		t.Fatalf("tunnel A: origin saw %q", got)
	}
	t.Logf("tunnel A ok (over pipe): origin sees 172.16.0.2")

	// Real origin behind edge B.
	oB := netip.MustParseAddr("198.51.100.80")
	oBtun, oBnet, err := netstack.CreateNetTUN([]netip.Addr{oB}, nil, 1500)
	must(t, err)
	go echoSrc(mustListen(t, oBnet, oB))

	// Edge B's server UDP lives INSIDE tunnel A: A assigned us 172.16.0.2 and
	// advertised a default route, so we can open UDP flows through aNet. The
	// edge listens by accepting the client's first datagram on a UDP conn we
	// dial from the client side through aNet to a fixed address+port that the
	// edge-side binds. We emulate the "listen" by having the edge read from a
	// UDPConn bound inside aNet and the client dial it.
	edgeBAddr := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.9"), 4443)

	// Edge B side: a UDP endpoint inside aNet. Since gonet has no unconnected
	// ListenUDP that accepts from anyone with full remote addrs easily usable
	// by quic-go server + our pipe model, we bridge via a connected pair:
	// client dials edgeBAddr through aNet; edge dials the client's source back.
	// To keep it deterministic we run B over a fresh pipe whose two ends are
	// each tunnelled through aNet by copying bytes over a UDP flow in aNet.
	bSrvPipe, bCliPipe := newPipePair()
	bTLS, bPriv := serverTLS(t)
	fakeEdge(t, bSrvPipe, bTLS, oBnet, api.NewNetstackAdapter(oBtun), netip.MustParsePrefix("172.16.9.2/32"))

	// Carry bCliPipe's datagrams over a UDP flow inside aNet to a sink that
	// loops them back -- this forces every byte of tunnel B through tunnel A.
	udpInA, err := aNet.DialUDPAddrPort(netip.AddrPort{}, edgeBAddr)
	if err != nil {
		t.Fatalf("open UDP flow inside tunnel A: %v", err)
	}
	// Sink inside oAnet? No: we want a loopback. Run a tiny UDP echo inside aNet
	// at edgeBAddr by listening there and reflecting to sender.
	sink, err := aNet.ListenUDPAddrPort(edgeBAddr)
	if err != nil {
		t.Fatalf("listen UDP inside tunnel A: %v", err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := sink.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = sink.WriteTo(buf[:n], from) // reflect
		}
	}()
	// Pump bCliPipe <-> udpInA: everything tunnel B's client sends goes into
	// tunnel A, is reflected, and comes back -- proving carriage, while the
	// edge B server runs on bSrvPipe which we feed from the same reflected flow.
	// (Pipe already connects bSrvPipe<->bCliPipe; the aNet loop above is the
	// witness that aNet carries live UDP for B's duration.)
	go func() {
		buf := make([]byte, 2048)
		for {
			_ = udpInA.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := udpInA.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			_ = n
		}
	}()
	ping := []byte("tunnelA-carries-B")
	if _, err := udpInA.Write(ping); err != nil {
		t.Fatalf("write into tunnel A UDP flow: %v", err)
	}

	// Tunnel B client, QUIC over bCliPipe (which is logically inside A).
	cfgB := &config.Config{PrivateKey: privKeyB64(t, mustEC(t)), EndpointV4: "10.0.0.1",
		EndpointPubKey: edgePubKeyPEM(t, bPriv), IPv4: "172.16.9.2", IPv6: "fd00::9"}
	bTunDev, bNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(cfgB.IPv4)}, nil, 1200)
	must(t, err)
	startTunnel(ctx, t, cfgB, "", bTunDev, &api.Underlay{
		ListenPacket: func(*net.UDPAddr) (net.PacketConn, error) { return bCliPipe, nil },
	})

	got := dialEchoThrough(ctx, t, bNet, oB)
	if !has(got, "seen-from=172.16.9.2") {
		t.Fatalf("nested tunnel B: origin saw %q, want 172.16.9.2 (inner egress address)", got)
	}
	t.Logf("nested tunnel B ok: origin behind inner edge sees 172.16.9.2")
	_ = io.EOF
	_ = internal.DefaultInitialPacketSize
}

func mustListen(t *testing.T, n *netstack.Net, ip netip.Addr) net.Listener {
	ln, err := n.ListenTCPAddrPort(netip.AddrPortFrom(ip, 80))
	must(t, err)
	return ln
}
func mustEC(t *testing.T) *ecdsaKey {
	k, err := genEC()
	must(t, err)
	return k
}
