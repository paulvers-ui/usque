//go:build android && !cgo
// +build android,!cgo

package main

import (
	"log"
	"net"

	"github.com/Diniboy1123/usque/internal/doh"
)

// Android has no /etc/resolv.conf, so Go's resolver would fall back to localhost:53.
// Every lookup through net.DefaultResolver -- including the WARP registration API --
// goes over DNS-over-HTTPS to Cloudflare instead, DNSSEC-checked (see package doh).
//
// There is no fallback to plain UDP/53. The resolver this replaces raced UDP "dials"
// to Cloudflare's v6 and v4 addresses and took whichever socket opened first; a UDP
// dial succeeds without any network round trip, so on networks with a dead IPv6 path
// it often picked v6 and registration timed out.
func init() {
	client, err := doh.New(doh.Options{})
	if err != nil {
		log.Fatalf("dns: DoH resolver: %v", err)
	}
	net.DefaultResolver = client.Resolver()
}
