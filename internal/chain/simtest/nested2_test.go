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
	"github.com/Diniboy1123/usque/internal/chain"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// serverPacketConnInA is a net.PacketConn for quic-go's server that lives
// genuinely inside tunnel A: it is an unconnected UDP endpoint opened on aNet.
// quic-go reads client datagrams from it (with real remote AddrPorts) and
// writes replies back through aNet. No side pipe.
func TestTwoWarpHopsTrulyNested(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// --- tunnel A over a pipe (WARP1 role), origin behind A for sanity ---
	oA := netip.MustParseAddr("192.0.2.80")
	oAtun, oAnet, err := netstack.CreateNetTUN([]netip.Addr{oA}, nil, 1500)
	must(t, err)
	go echoSrc(mustListen(t, oAnet, oA))
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

	// --- edge B listening on a UDP endpoint INSIDE tunnel A ---
	oB := netip.MustParseAddr("198.51.100.80")
	oBtun, oBnet, err := netstack.CreateNetTUN([]netip.Addr{oB}, nil, 1500)
	must(t, err)
	go echoSrc(mustListen(t, oBnet, oB))

	// This is the real nesting: B's server UDP socket is opened on aNet, and B's
	// client Underlay also dials through aNet. Every QUIC datagram of tunnel B
	// is carried as UDP inside tunnel A.
	edgeBBind := netip.AddrPortFrom(netip.MustParseAddr("172.16.0.2"), 4443)
	bServerPC, err := aNet.ListenUDPAddrPort(edgeBBind)
	if err != nil {
		t.Fatalf("edge B listen inside tunnel A: %v", err)
	}
	bTLS, bPriv := serverTLS(t)
	fakeEdge(t, bServerPC, bTLS, oBnet, api.NewNetstackAdapter(oBtun), netip.MustParsePrefix("172.16.9.2/32"))

	// Tunnel B client: endpoint is edgeBBind (reachable only inside A), and the
	// Underlay dials UDP through aNet.
	cfgB := &config.Config{PrivateKey: privKeyB64(t, mustEC(t)),
		EndpointV4: edgeBBind.Addr().String(), EndpointPubKey: edgePubKeyPEM(t, bPriv),
		IPv4: "172.16.9.2", IPv6: "fd00::9"}
	bTunDev, bNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(cfgB.IPv4)}, nil, 1200)
	must(t, err)

	startTunnelPort(ctx, t, cfgB, bTunDev, chainUnderlayUDP(aNet), int(edgeBBind.Port()))

	got := dialEchoThrough(ctx, t, bNet, oB)
	if !has(got, "seen-from=172.16.9.2") {
		t.Fatalf("truly-nested tunnel B: origin saw %q, want 172.16.9.2", got)
	}
	t.Logf("TRULY nested: tunnel B QUIC runs inside tunnel A; inner origin sees 172.16.9.2")
	_ = io.EOF
}

// chainUnderlayUDP builds an Underlay whose UDP sockets are opened on n (an
// outer tunnel stack). This is what chain.UnderlayOf does; re-expressed here so
// the test does not depend on unexported helpers.
func chainUnderlayUDP(n *netstack.Net) *api.Underlay {
	return chain.UnderlayOf(n)
}
