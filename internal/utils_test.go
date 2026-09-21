package internal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// loopbackTLS returns a server config with a fresh self-signed certificate for 127.0.0.1
// and a client config that trusts only that certificate.
func loopbackTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	server = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"usque-test"},
	}
	client = &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"usque-test"}}
	return server, client
}

// TestDefaultQuicConfigFitsFullTunnelPacket checks that a CONNECT-IP datagram carrying a
// full 1280-byte tunnel packet can be sent right after the handshake. At quic-go's 1280-byte
// starting size it cannot: connect-ip-go then drops the packet, which stalled TLS handshakes
// through the tunnel until path MTU discovery grew the packet size.
func TestDefaultQuicConfigFitsFullTunnelPacket(t *testing.T) {
	// Context ID 0 (one byte) followed by the IP packet.
	datagram := make([]byte, 1+1280)

	for _, tc := range []struct {
		name       string
		packetSize uint16
		wantFit    bool
	}{
		{"default", DefaultInitialPacketSize, true},
		{"1280", 1280, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverTLS, clientTLS := loopbackTLS(t)
			ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() {
				if conn, err := ln.Accept(ctx); err == nil {
					<-ctx.Done()
					_ = conn.CloseWithError(0, "")
				}
			}()

			conn, err := quic.DialAddr(ctx, ln.Addr().String(), clientTLS, DefaultQuicConfig(0, tc.packetSize))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.CloseWithError(0, "") }()

			err = conn.SendDatagram(datagram)
			var tooLarge *quic.DatagramTooLargeError
			switch {
			case tc.wantFit && err != nil:
				t.Fatalf("SendDatagram(%d bytes) at packet size %d: %v", len(datagram), tc.packetSize, err)
			case !tc.wantFit && !errors.As(err, &tooLarge):
				t.Fatalf("SendDatagram(%d bytes) at packet size %d: got %v, want DatagramTooLargeError", len(datagram), tc.packetSize, err)
			}
		})
	}
}
