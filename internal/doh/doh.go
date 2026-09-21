// Package doh resolves names with DNS-over-HTTPS (RFC 8484).
//
// DNSSEC is validated by the upstream resolver (Cloudflare's 1.1.1.1 by default):
// every query sets the DNSSEC OK bit, a bogus answer comes back as SERVFAIL with an
// Extended DNS Error (RFC 8914), and a validated one carries the AD bit. Trusting AD
// is sound only because the channel to that resolver is authenticated TLS (see
// package trust). There is deliberately no fallback to plain UDP/53.
package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/internal/trust"
	"golang.org/x/net/dns/dnsmessage"
)

// DefaultEndpoints are Cloudflare's resolver addresses as IP literals, so reaching
// them needs no bootstrap DNS. IPv4 comes first: on networks that advertise IPv6
// without a working route, trying v6 first stalls every lookup. All four are IP SANs
// in the resolver's certificate.
var DefaultEndpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://1.0.0.1/dns-query",
	"https://[2606:4700:4700::1111]/dns-query",
	"https://[2606:4700:4700::1001]/dns-query",
}

// DefaultSecureNames must come back DNSSEC-authenticated even in ModeValidate. The
// WARP API zone is signed, so an unauthenticated answer for it means something
// stripped the signatures on the way. (engage.cloudflareclient.com is not signed,
// which is why ModeStrict is not the default.)
var DefaultSecureNames = []string{"api.cloudflareclient.com"}

// Mode selects how DNSSEC results are enforced.
type Mode int

const (
	// ModeValidate rejects bogus answers and requires authentication for the secure
	// names; answers from unsigned zones are otherwise accepted.
	ModeValidate Mode = iota
	// ModeStrict requires every answer to be DNSSEC-authenticated.
	ModeStrict
	// ModeOff still uses DoH but neither asks for nor checks DNSSEC status.
	ModeOff
)

// ParseMode maps the --dnssec flag values to a Mode.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(s) {
	case "", "validate":
		return ModeValidate, nil
	case "strict":
		return ModeStrict, nil
	case "off":
		return ModeOff, nil
	}
	return 0, fmt.Errorf("doh: unknown DNSSEC mode %q (want validate, strict or off)", s)
}

var (
	// ErrBogus means the resolver found the answer's DNSSEC signatures invalid.
	ErrBogus = errors.New("doh: DNSSEC validation failed")
	// ErrInsecure means an answer that had to be DNSSEC-authenticated was not.
	ErrInsecure = errors.New("doh: answer is not DNSSEC-authenticated")

	errNXDomain = errors.New("doh: no such host")
)

const (
	defaultTimeout = 5 * time.Second
	ednsPayload    = 1232
	optionPadding  = 12 // RFC 7830
	optionEDE      = 15 // RFC 8914
	paddingBlock   = 128
	maxMessage     = 65535
	minCacheTTL    = 10 * time.Second
	maxCacheTTL    = 5 * time.Minute
	maxCacheSize   = 1024
)

// Options configures a Client. The zero value resolves through DefaultEndpoints over
// the host network in ModeValidate.
type Options struct {
	// Endpoints are DoH URLs tried in order. IP-literal hosts need no bootstrap lookup.
	Endpoints []string
	// Dial opens the connection to an endpoint, e.g. through the MASQUE tunnel. Nil
	// dials over the host network.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// RootCAs verifies the endpoints. Nil uses trust.Roots.
	RootCAs *x509.CertPool
	// Timeout bounds each endpoint attempt. Zero means 5s.
	Timeout time.Duration
	// Mode is the DNSSEC enforcement level.
	Mode Mode
	// SecureNames must validate in ModeValidate. Nil means DefaultSecureNames.
	SecureNames []string
}

// Client is a DNS-over-HTTPS resolver. It is safe for concurrent use.
type Client struct {
	endpoints []string
	http      *http.Client
	timeout   time.Duration
	mode      Mode
	secure    map[string]bool

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ips     []net.IP
	expires time.Time
}

// New returns a Client for opts.
func New(opts Options) (*Client, error) {
	endpoints := opts.Endpoints
	if len(endpoints) == 0 {
		endpoints = DefaultEndpoints
	}
	for _, ep := range endpoints {
		u, err := url.Parse(ep)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("doh: invalid endpoint %q (want an https:// URL)", ep)
		}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	dial := opts.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext
	}
	rootCAs := opts.RootCAs
	if rootCAs == nil {
		rootCAs = trust.Roots()
	}
	secureNames := opts.SecureNames
	if secureNames == nil {
		secureNames = DefaultSecureNames
	}
	secure := make(map[string]bool, len(secureNames))
	for _, n := range secureNames {
		secure[canonical(n)] = true
	}

	return &Client{
		endpoints: endpoints,
		http: &http.Client{
			Transport: &http.Transport{
				DialContext:         dial,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: rootCAs},
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: timeout,
				MaxIdleConns:        4,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		timeout: timeout,
		mode:    opts.Mode,
		secure:  secure,
		cache:   make(map[string]cacheEntry),
	}, nil
}

// LookupIP resolves host to its IPv4 addresses followed by its IPv6 ones. An IP
// literal is returned as-is. A DNSSEC failure for either family fails the whole
// lookup: it means answers for this name are being tampered with.
func (c *Client) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	key := canonical(host)
	if ips, ok := c.cached(key); ok {
		return ips, nil
	}
	name, err := dnsmessage.NewName(key + ".")
	if err != nil {
		return nil, fmt.Errorf("doh: invalid name %q: %w", host, err)
	}

	var a, aaaa answer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a = c.lookup(ctx, name, dnsmessage.TypeA) }()
	go func() { defer wg.Done(); aaaa = c.lookup(ctx, name, dnsmessage.TypeAAAA) }()
	wg.Wait()

	for _, r := range []answer{a, aaaa} {
		if errors.Is(r.err, ErrBogus) || errors.Is(r.err, ErrInsecure) {
			return nil, r.err
		}
	}
	ips := append(a.ips, aaaa.ips...)
	if len(ips) == 0 {
		if errors.Is(a.err, errNXDomain) || errors.Is(aaaa.err, errNXDomain) || (a.err == nil && aaaa.err == nil) {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return nil, errors.Join(a.err, aaaa.err)
	}
	c.store(key, ips, min(a.ttl, aaaa.ttl))
	return ips, nil
}

type answer struct {
	ips []net.IP
	ttl time.Duration
	err error
}

func (c *Client) lookup(ctx context.Context, name dnsmessage.Name, qtype dnsmessage.Type) answer {
	q := dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}
	msg, _, err := c.exchange(ctx, q)
	if err != nil {
		return answer{err: err}
	}
	if msg.RCode == dnsmessage.RCodeNameError {
		return answer{err: errNXDomain}
	}
	res := answer{ttl: maxCacheTTL}
	for _, rr := range msg.Answers {
		var ip net.IP
		switch body := rr.Body.(type) {
		case *dnsmessage.AResource:
			if qtype == dnsmessage.TypeA {
				ip = net.IPv4(body.A[0], body.A[1], body.A[2], body.A[3])
			}
		case *dnsmessage.AAAAResource:
			if qtype == dnsmessage.TypeAAAA {
				ip = make(net.IP, net.IPv6len)
				copy(ip, body.AAAA[:])
			}
		}
		if ip == nil {
			continue
		}
		res.ips = append(res.ips, ip)
		res.ttl = min(res.ttl, time.Duration(rr.Header.TTL)*time.Second)
	}
	return res
}

// exchange asks each endpoint in turn until one gives an acceptable answer, returning
// it both parsed and raw. DNSSEC failures are final: the other endpoints are the same
// resolver, and a bogus answer means tampering, not an unreachable endpoint.
func (c *Client) exchange(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, []byte, error) {
	query, err := buildQuery(q, c.mode != ModeOff)
	if err != nil {
		return nil, nil, err
	}
	var errs []error
	for _, ep := range c.endpoints {
		msg, raw, err := c.post(ctx, ep, query)
		if err == nil {
			if err = c.check(q, msg); err == nil {
				return msg, raw, nil
			}
			if errors.Is(err, ErrBogus) || errors.Is(err, ErrInsecure) {
				return nil, nil, err
			}
		}
		errs = append(errs, fmt.Errorf("%s: %w", ep, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, nil, errors.Join(errs...)
}

func (c *Client) post(ctx context.Context, endpoint string, query []byte) (*dnsmessage.Message, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/dns-message" {
		return nil, nil, fmt.Errorf("unexpected content type %q", resp.Header.Get("Content-Type"))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxMessage+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > maxMessage {
		return nil, nil, errors.New("response too large")
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return nil, nil, err
	}
	return &msg, raw, nil
}

// check validates a response against its question and the DNSSEC policy.
func (c *Client) check(q dnsmessage.Question, msg *dnsmessage.Message) error {
	if !msg.Response || msg.ID != 0 || len(msg.Questions) != 1 ||
		msg.Questions[0].Type != q.Type || !strings.EqualFold(msg.Questions[0].Name.String(), q.Name.String()) {
		return errors.New("response does not match the query")
	}
	switch msg.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	case dnsmessage.RCodeServerFailure:
		if code, ok := extendedError(msg); ok && dnssecFailure(code) {
			return fmt.Errorf("%w for %s (extended DNS error %d)", ErrBogus, q.Name, code)
		}
		return errors.New("SERVFAIL")
	default:
		return fmt.Errorf("rcode %v", msg.RCode)
	}
	if c.mode == ModeOff || msg.AuthenticData {
		return nil
	}
	if c.mode == ModeStrict || c.secure[canonical(q.Name.String())] {
		return fmt.Errorf("%w: %s", ErrInsecure, q.Name)
	}
	return nil
}

// extendedError returns the INFO-CODE of the first Extended DNS Error option.
func extendedError(msg *dnsmessage.Message) (uint16, bool) {
	for _, rr := range msg.Additionals {
		opt, ok := rr.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		for _, o := range opt.Options {
			if o.Code == optionEDE && len(o.Data) >= 2 {
				return binary.BigEndian.Uint16(o.Data), true
			}
		}
	}
	return 0, false
}

// dnssecFailure reports whether an RFC 8914 INFO-CODE describes a DNSSEC failure:
// 1-2 unsupported algorithm or digest, 5 indeterminate, 6 bogus, 7-8 signature
// expired or not yet valid, 9-12 missing DNSKEY, RRSIGs, zone key bit or NSEC.
func dnssecFailure(code uint16) bool {
	switch code {
	case 1, 2, 5, 6, 7, 8, 9, 10, 11, 12:
		return true
	}
	return false
}

// buildQuery packs q with ID 0 (RFC 8484 §4.1), EDNS(0) with the DNSSEC OK bit when
// asked, and padding to a 128-byte multiple (RFC 8467) so the query size does not
// give the name away through the encrypted stream.
func buildQuery(q dnsmessage.Question, dnssecOK bool) ([]byte, error) {
	msg, err := packQuery(q, dnssecOK, 0)
	if err != nil {
		return nil, err
	}
	if rem := len(msg) % paddingBlock; rem != 0 {
		return packQuery(q, dnssecOK, paddingBlock-rem)
	}
	return msg, nil
}

func packQuery(q dnsmessage.Question, dnssecOK bool, padding int) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(ednsPayload, dnsmessage.RCodeSuccess, dnssecOK); err != nil {
		return nil, err
	}
	pad := dnsmessage.Option{Code: optionPadding, Data: make([]byte, padding)}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{Options: []dnsmessage.Option{pad}}); err != nil {
		return nil, err
	}
	return b.Finish()
}

func (c *Client) cached(key string) ([]net.IP, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.ips, true
}

func (c *Client) store(key string, ips []net.IP, ttl time.Duration) {
	ttl = min(max(ttl, minCacheTTL), maxCacheTTL)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= maxCacheSize {
		clear(c.cache)
	}
	c.cache[key] = cacheEntry{ips: ips, expires: time.Now().Add(ttl)}
}

func canonical(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}
