package simtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun"
)

type tunDeviceT = tun.Device

func genEC() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// startTunnel wires MaintainTunnel the way chain.StartWarp does, over the given
// Underlay, using insecure pinning-off against the fake edge's self-signed cert.
func startTunnel(ctx context.Context, t *testing.T, c *config.Config, _ string, dev tun.Device, ul *api.Underlay) {
	priv, err := c.GetEcPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := internal.GenerateCert(priv, &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// insecure=true: the fake edge cert is self-signed and not pinned.
	tlsConfig, err := api.PrepareTlsConfig(priv, &priv.PublicKey, cert, "fake-edge", true)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := c.SelectEndpoint(false, false, 443)
	if err != nil {
		t.Fatal(err)
	}
	go api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
		TLSConfig:         tlsConfig,
		KeepalivePeriod:   10 * time.Second,
		InitialPacketSize: internal.DefaultInitialPacketSize,
		Endpoint:          ep,
		Device:            api.NewNetstackAdapter(dev),
		MTU:               1280,
		ReconnectDelay:    500 * time.Millisecond,
		AlwaysReconnect:   true,
		Underlay:          ul,
	})
}

func startTunnelPort(ctx context.Context, t *testing.T, c *config.Config, dev tunDeviceT, ul *api.Underlay, port int) {
	priv, err := c.GetEcPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := internal.GenerateCert(priv, &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := api.PrepareTlsConfig(priv, &priv.PublicKey, cert, "fake-edge", true)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := c.SelectEndpoint(false, false, port)
	if err != nil {
		t.Fatal(err)
	}
	go api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
		TLSConfig: tlsConfig, KeepalivePeriod: 10 * time.Second,
		InitialPacketSize: internal.DefaultInitialPacketSize, Endpoint: ep,
		Device: api.NewNetstackAdapter(dev), MTU: 1200, ReconnectDelay: 500 * time.Millisecond,
		AlwaysReconnect: true, Underlay: ul,
	})
}
