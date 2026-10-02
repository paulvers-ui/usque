package simtest

// A minimal in-memory Cloudflare-MASQUE stand-in: a real HTTP/3 server speaking
// real CONNECT-IP (connect-ip-go), bridged to a userspace "internet" stack that
// runs an IP-echo origin. Used to exercise usque's real client + Underlay path
// without touching Cloudflare.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	wgconn "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// pktConnBind lets quic-go's server run its UDP over a net.PacketConn we control
// (here, a pipe to the client), so no real sockets/ports are used.
type pipePacketConn struct {
	rx     chan pkt
	tx     chan pkt
	local  net.Addr
	mu     sync.Mutex
	closed bool
}
type pkt struct {
	b    []byte
	addr net.Addr
}
type udpAddr struct{ name string }

func (u udpAddr) Network() string { return "udp" }
func (u udpAddr) String() string  { return u.name }

func newPipePair() (*pipePacketConn, *pipePacketConn) {
	a2b := make(chan pkt, 256)
	b2a := make(chan pkt, 256)
	a := &pipePacketConn{rx: b2a, tx: a2b, local: udpAddr{"10.0.0.1:443"}}
	b := &pipePacketConn{rx: a2b, tx: b2a, local: udpAddr{"10.0.0.2:40000"}}
	return a, b
}
func (c *pipePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pk := <-c.rx:
		return copy(p, pk.b), pk.addr, nil
	case <-time.After(30 * time.Second):
		return 0, nil, &net.OpError{Op: "read", Err: errTimeout{}}
	}
}
func (c *pipePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	b := append([]byte(nil), p...)
	select {
	case c.tx <- pkt{b: b, addr: c.local}:
		return len(p), nil
	case <-time.After(5 * time.Second):
		return 0, net.ErrClosed
	}
}
func (c *pipePacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *pipePacketConn) LocalAddr() net.Addr                { return c.local }
func (c *pipePacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *pipePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pipePacketConn) SetWriteDeadline(t time.Time) error { return nil }

type errTimeout struct{}

func (errTimeout) Error() string   { return "timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }

func serverTLS(t testingT) (*tls.Config, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake-edge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	must(t, err)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		NextProtos:   []string{http3.NextProtoH3},
	}, priv
}

// fakeEdge runs a MASQUE server over conn and routes proxied packets into inet,
// an origin netstack. clientPrefix is assigned to the client inside the tunnel.
func fakeEdge(t testingT, conn net.PacketConn, tlsc *tls.Config, inet *netstack.Net, inetTun tunReadWriter, clientPrefix netip.Prefix) *http3.Server {
	tmpl := uritemplate.MustNew("https://cloudflareaccess.com")
	var p connectip.Proxy
	srv := &http3.Server{
		TLSConfig:       tlsc,
		EnableDatagrams: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req, err := connectip.ParseRequest(r, tmpl, "cf-connect-ip")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			ipc, err := p.Proxy(w, req)
			if err != nil {
				return
			}
			ctx := context.Background()
			_ = ipc.AssignAddresses(ctx, []netip.Prefix{clientPrefix})
			_ = ipc.AdvertiseRoute(ctx, []connectip.IPRoute{{
				StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255"),
			}})
			// edge -> internet
			go func() {
				for {
					pktBuf, err := ipc.ReadPacketZeroCopy(true)
					if err != nil {
						return
					}
					_ = inetTun.WritePacket(pktBuf)
				}
			}()
			// internet -> edge
			buf := make([]byte, 1500)
			for {
				n, err := inetTun.ReadPacket(buf)
				if err != nil {
					return
				}
				if _, err := ipc.WritePacket(buf[:n]); err != nil {
					return
				}
			}
		}),
	}
	go func() { _ = srv.Serve(conn) }()
	return srv
}

type tunReadWriter interface {
	ReadPacket(buf []byte) (int, error)
	WritePacket(pkt []byte) error
}

type ecdsaKey = ecdsa.PrivateKey

type testingT interface {
	Fatalf(string, ...any)
	Logf(string, ...any)
}

func must(t testingT, err error) {
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
}

// edgePubKeyPEM returns the PEM the usque client pins against this edge.
func edgePubKeyPEM(t testingT, priv *ecdsa.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	must(t, err)
	return string(pemEncode("PUBLIC KEY", der))
}

func privKeyB64(t testingT, priv *ecdsa.PrivateKey) string {
	der, err := x509.MarshalECPrivateKey(priv)
	must(t, err)
	return b64(der)
}

var _ = fmt.Sprintf
var _ = quic.Config{}
var _ wgconn.Bind = nil
