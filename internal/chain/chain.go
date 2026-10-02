// Package chain nests tunnels inside one process:
//
//	apps -> SOCKS -> WARP2 (exit) -> wg0 -> WARP1 -> host network
//
// WARP1 hides the user from the ISP, wg0 gives a new location and WARP2
// "washes" the wg0 server IP into a Cloudflare egress IP. Every hop is a
// userspace network stack; each hop dials its transport through the stack
// of the hop below it, so nothing touches the host routing table.
package chain

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/internal/doh"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	// wgOverhead4/6: WireGuard data header+tag (32) + UDP (8) + IP header.
	wgOverhead4 = 32 + 8 + 20
	wgOverhead6 = 32 + 8 + 40
	// quicMinPacket is the smallest UDP payload QUIC is allowed to run over.
	quicMinPacket = 1200
)

// WarpHop configures one MASQUE hop.
type WarpHop struct {
	Name              string
	Config            *config.Config
	SNI               string
	UseHTTP2          bool
	UseIPv6           bool
	ConnectPort       int
	InitialPacketSize uint16
	MTU               int
	Keepalive         time.Duration
	ReconnectDelay    time.Duration
	AlwaysReconnect   bool
	Insecure          bool
}

// UnderlayOf makes a tunnel's stack usable as the transport of the next hop.
func UnderlayOf(n *netstack.Net) *api.Underlay {
	if n == nil {
		return nil
	}
	return &api.Underlay{
		ListenPacket: func(ipv6 bool) (net.PacketConn, error) {
			a := netip.IPv4Unspecified()
			if ipv6 {
				a = netip.IPv6Unspecified()
			}
			return n.ListenUDPAddrPort(netip.AddrPortFrom(a, 0))
		},
		DialContext: n.DialContext,
	}
}

// StartWarp brings up a MASQUE hop over under (nil = host network) and returns
// the userspace stack that dials through it.
func StartWarp(ctx context.Context, h WarpHop, under *netstack.Net) (*netstack.Net, error) {
	c := h.Config
	privKey, err := c.GetEcPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	peerPub, err := c.GetEcEndpointPublicKey()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPub, cert, h.SNI, h.Insecure)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	return startWarpTLS(ctx, h, tlsConfig, under)
}

func startWarpTLS(ctx context.Context, h WarpHop, tlsConfig *tls.Config, under *netstack.Net) (*netstack.Net, error) {
	c := h.Config
	endpoint, err := c.SelectEndpoint(h.UseHTTP2, h.UseIPv6, h.ConnectPort)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	var addrs []netip.Addr
	for _, s := range []string{c.IPv4, c.IPv6} {
		if a, err := netip.ParseAddr(s); err == nil {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s: config has no tunnel addresses", h.Name)
	}
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, nil, h.MTU)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	transport := "HTTP/3"
	if h.UseHTTP2 {
		transport = "HTTP/2"
	}
	log.Printf("chain: %s up: %s via %s, tunnel MTU %d", h.Name, endpoint, transport, h.MTU)
	go api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
		TLSConfig:         tlsConfig,
		KeepalivePeriod:   h.Keepalive,
		InitialPacketSize: h.InitialPacketSize,
		Endpoint:          endpoint,
		Device:            api.NewNetstackAdapter(tunDev),
		MTU:               h.MTU,
		ReconnectDelay:    h.ReconnectDelay,
		AlwaysReconnect:   h.AlwaysReconnect,
		UseHTTP2:          h.UseHTTP2,
		Underlay:          UnderlayOf(under),
	})
	go func() { <-ctx.Done(); _ = tunDev.Close() }()
	return tnet, nil
}

// WGHop configures the WireGuard hop.
type WGHop struct {
	Config *WGConfig
	// UnderMTU is the MTU of the stack wg0 rides on (WARP1's tunnel MTU).
	UnderMTU int
	// Keepalive is used when the config does not set PersistentKeepalive.
	Keepalive int
	// Resolver resolves a hostname Endpoint; it should dial through the hop
	// below so the lookup is not visible to the ISP.
	Resolver *doh.Client
	LogLevel int
}

// WGMTU is the largest inner MTU that keeps wg0 packets inside the hop below.
func WGMTU(underMTU int, endpointV6 bool, configured int) int {
	over := wgOverhead4
	if endpointV6 {
		over = wgOverhead6
	}
	m := underMTU - over
	if configured > 0 && configured < m {
		m = configured
	}
	return m
}

func resolveEndpoint(ctx context.Context, host string, r *doh.Client) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), nil
	}
	if r == nil {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return netip.Addr{}, fmt.Errorf("resolve %s: %v", host, err)
		}
		return pickV4(ips), nil
	}
	ips, err := r.LookupIP(ctx, host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %s through WARP1: %v", host, err)
	}
	var out []netip.Addr
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return pickV4(out), nil
}

// pickV4 prefers IPv4: its smaller header leaves 20 more bytes of MTU.
func pickV4(ips []netip.Addr) netip.Addr {
	for _, a := range ips {
		if a.Unmap().Is4() {
			return a.Unmap()
		}
	}
	return ips[0]
}

// StartWG brings up wg0 with its UDP carried inside under and returns the
// stack that dials through wg0, plus the MTU chosen for it.
func StartWG(ctx context.Context, h WGHop, under *netstack.Net) (*netstack.Net, int, error) {
	cfg := h.Config
	host, port, err := SplitEndpoint(cfg.Peers[0].Endpoint)
	if err != nil {
		return nil, 0, err
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	addr, err := resolveEndpoint(rctx, host, h.Resolver)
	cancel()
	if err != nil {
		return nil, 0, fmt.Errorf("wg0: %w", err)
	}
	ep := netip.AddrPortFrom(addr, port)

	mtu := WGMTU(h.UnderMTU, addr.Is6(), cfg.MTU)
	if cfg.MTU > mtu {
		log.Printf("chain: wg0 MTU %d does not fit inside WARP1 (%d); using %d", cfg.MTU, h.UnderMTU, mtu)
	}
	var addrs []netip.Addr
	for _, p := range cfg.Addresses {
		a := p.Addr()
		if a.Is6() && mtu < 1280 {
			// IPv6 needs a 1280-byte link; the exit hop uses IPv4 anyway.
			log.Printf("chain: wg0 MTU %d < 1280, ignoring IPv6 address %s", mtu, a)
			continue
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil, 0, fmt.Errorf("wg0: no usable IPv4 Address at MTU %d", mtu)
	}
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, cfg.DNS, mtu)
	if err != nil {
		return nil, 0, fmt.Errorf("wg0: %w", err)
	}
	keepalive := cfg.Peers[0].PersistentKeepalive
	if keepalive <= 0 {
		keepalive = h.Keepalive
	}
	dev := device.NewDevice(tunDev, newNetstackBind(under), device.NewLogger(h.LogLevel, "wg0: "))
	if err := dev.IpcSet(cfg.UAPI(ep, keepalive)); err != nil {
		dev.Close()
		return nil, 0, fmt.Errorf("wg0: config rejected: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, 0, fmt.Errorf("wg0: %w", err)
	}
	log.Printf("chain: wg0 up: peer %s, inner MTU %d, keepalive %ds", ep, mtu, keepalive)
	go func() { <-ctx.Done(); dev.Close() }()
	return tnet, mtu, nil
}

// ExitTransportFits reports whether the exit hop can run QUIC through wg0.
// QUIC needs 1200-byte UDP payloads both ways, and Cloudflare may send up to
// 1452, which a wg0 inside WARP1 (MTU ~1220) cannot carry.
func ExitTransportFits(wgMTU int) bool {
	return wgMTU-28 >= 1452
}
