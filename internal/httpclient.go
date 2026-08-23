package internal

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// APIClient is the HTTP client used for every api.cloudflareclient.com call
// (register, patch, account, delete). It exists because http.DefaultClient's
// dialer was reaching the API over IPv6 on networks that have no IPv6 route,
// producing:
//
//	Failed to register: failed to send request:
//	Post "https://api.cloudflareclient.com/v0a4471/reg":
//	dial tcp [2606:4700::6810:1854]:443: connect: network is unreachable
//
// api.cloudflareclient.com publishes both A and AAAA records. Go's dual-stack
// dialer is supposed to race them, but on a host with an IPv6 address that has
// no working route (very common on mobile carriers that advertise IPv6 without
// end-to-end connectivity, and inside VPN/tun setups that carry v4 only) the
// v6 attempt can be selected and fail outright before v4 is usefully tried.
// Registration then fails even though the network is perfectly usable over v4
// -- and it's the one request that must succeed before any MASQUE tunnel
// exists to carry it, so there's no tunnel to fall back on.
//
// Note this is orthogonal to the --ipv6 flag on socks/http-proxy/native-tun:
// that selects the address family of the MASQUE *endpoint*, and never applied
// to the registration API at all.
var APIClient = &http.Client{
	Timeout: 60 * time.Second,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialPreferIPv4,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// dialPreferIPv4 tries IPv4 first and only then falls back to the caller's
// original network. Deliberately a preference and not a hard override, so
// IPv6-only networks keep working: "tcp4" simply fails fast there (no A record
// reachable / no v4 address assigned) and the dual-stack path takes over.
//
// Set USQUE_FORCE_IPV4=1 to make it a hard requirement instead -- useful for
// pinning behaviour on a host where the v6 path is broken in a way that hangs
// rather than erroring.
func dialPreferIPv4(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Only "tcp" is ambiguous; an explicit tcp4/tcp6 from the caller is honoured.
	if network != "tcp" {
		return d.DialContext(ctx, network, addr)
	}

	conn, v4err := d.DialContext(ctx, "tcp4", addr)
	if v4err == nil {
		return conn, nil
	}

	// Don't retry if the caller gave up (timeout/cancel) -- that's not an
	// address-family problem and retrying would just double the wait.
	if ctx.Err() != nil {
		return nil, v4err
	}

	if forceIPv4() {
		return nil, v4err
	}

	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		// Surface both, so "network is unreachable" on one family isn't
		// mistaken for the whole host being unreachable.
		return nil, fmt.Errorf("ipv4: %v; %s: %w", v4err, network, err)
	}
	return conn, nil
}

func forceIPv4() bool {
	switch os.Getenv("USQUE_FORCE_IPV4") {
	case "1", "true", "yes":
		return true
	}
	return false
}
