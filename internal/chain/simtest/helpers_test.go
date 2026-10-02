package simtest

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
)

func key(t *testing.T) (priv device.NoisePrivateKey, pub device.NoisePublicKey) {
	t.Helper()
	if _, err := crand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pub[:], p)
	return priv, pub
}

func uapi(priv device.NoisePrivateKey, peerPub device.NoisePublicKey, endpoint, allowed string, keepalive int) string {
	return fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\nallowed_ip=%s\n",
		hex.EncodeToString(priv[:]), hex.EncodeToString(peerPub[:]), endpoint, keepalive, allowed)
}
