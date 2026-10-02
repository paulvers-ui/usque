package chain

import (
	"strings"
	"testing"
)

const sampleConf = `[Interface]
PrivateKey = MUUZPL/VDmpYGnxcCUDWtnyxWxRPzQZg6xNMbSkUV6M=
Address = 10.9.0.2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = BRAXZTb4ukmAGaFgiEPa/dw44hpRd9PcFI617ee9wR0=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
`

func TestParseWGConfig(t *testing.T) {
	c, err := ParseWGConfig(strings.NewReader(sampleConf))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Peers) != 1 || c.Peers[0].Endpoint != "vpn.example.com:51820" {
		t.Fatalf("bad peer: %+v", c.Peers)
	}
	if c.Peers[0].PersistentKeepalive != 25 {
		t.Fatalf("keepalive: %d", c.Peers[0].PersistentKeepalive)
	}
	host, port, err := SplitEndpoint(c.Peers[0].Endpoint)
	if err != nil || host != "vpn.example.com" || port != 51820 {
		t.Fatalf("split: %s %d %v", host, port, err)
	}
}

func TestRejectAmnezia(t *testing.T) {
	conf := strings.Replace(sampleConf, "MTU = 1280", "MTU = 1280\nJc = 4", 1)
	if _, err := ParseWGConfig(strings.NewReader(conf)); err == nil {
		t.Fatal("expected AmneziaWG config to be rejected")
	} else if !strings.Contains(err.Error(), "AmneziaWG") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestWGMTU(t *testing.T) {
	// WARP1 inner MTU 1280, IPv4 endpoint -> 1280-60 = 1220.
	if got := WGMTU(1280, false, 0); got != 1220 {
		t.Fatalf("v4 MTU = %d, want 1220", got)
	}
	// IPv6 endpoint -> 1280-80 = 1200.
	if got := WGMTU(1280, true, 0); got != 1200 {
		t.Fatalf("v6 MTU = %d, want 1200", got)
	}
	// Configured smaller value wins.
	if got := WGMTU(1280, false, 1180); got != 1180 {
		t.Fatalf("configured MTU = %d, want 1180", got)
	}
}

func TestExitTransportFits(t *testing.T) {
	// Through a 1220-MTU wg0, QUIC (needs 1452-byte datagrams) does NOT fit,
	// so the exit must fall back to HTTP/2.
	if ExitTransportFits(1220) {
		t.Fatal("QUIC should not fit through wg0 at MTU 1220")
	}
	if ExitTransportFits(1200) {
		t.Fatal("QUIC should not fit through wg0 at MTU 1200")
	}
}
