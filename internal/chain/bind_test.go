package chain

import (
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TestNetstackBindSendDoesNotBlock pins the start-up fix: while the tunnel under
// wg0 is not connected, nothing reads its netstack's outbound packets, and a
// wireguard-go netstack hands those over an unbuffered channel. A synchronous
// write then blocked wg0's first handshake send inside dev.Up(), so the chain's
// SOCKS port only opened once WARP1 had connected (and the app gave up first).
func TestNetstackBindSendDoesNotBlock(t *testing.T) {
	// A stack whose TUN side is never read: WARP1 still connecting. It is not
	// closed: the writer stays blocked on the stack's unbuffered channel, and
	// closing that channel under a blocked sender panics.
	_, under, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("172.16.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}

	b := newNetstackBind(under)
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	ep, err := b.ParseEndpoint("192.0.2.1:51820")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		pkt := make([]byte, 148) // a handshake initiation's size
		// More than the queue holds, so the drop path is exercised too.
		for i := 0; i < 2*sendQueueLen; i++ {
			if err := b.Send([][]byte{pkt}, ep); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send blocked while the stack below was not draining")
	}
}
