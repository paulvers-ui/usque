package doh

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// reply is what a test endpoint answers with.
type reply struct {
	status int // HTTP status; 0 means 200 with a DNS message
	rcode  dnsmessage.RCode
	ad     bool
	ede    uint16 // Extended DNS Error INFO-CODE; 0 means none
	ips    []net.IP
}

type testEndpoint struct {
	*httptest.Server
	hits atomic.Int32

	mu        sync.Mutex
	lastQuery []byte
}

// Test endpoints listen on in-memory pipes rather than loopback TCP, so there is no
// connection for TLS-intercepting software on the host (antivirus "HTTPS scanning")
// to re-sign, which would make every handshake fail verification.
var (
	pipeMu    sync.Mutex
	pipePort  = 40000
	listeners = map[string]*pipeListener{}
)

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

type pipeListener struct {
	addr   pipeAddr
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	pipeMu.Lock()
	defer pipeMu.Unlock()
	pipePort++
	l := &pipeListener{
		addr:   pipeAddr(fmt.Sprintf("127.0.0.1:%d", pipePort)),
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
	listeners[string(l.addr)] = l
	return l
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		pipeMu.Lock()
		delete(listeners, string(l.addr))
		pipeMu.Unlock()
	})
	return nil
}

func (l *pipeListener) Addr() net.Addr { return l.addr }

// pipeDial connects to the test endpoint registered at addr.
func pipeDial(ctx context.Context, _, addr string) (net.Conn, error) {
	pipeMu.Lock()
	l := listeners[addr]
	pipeMu.Unlock()
	if l == nil {
		return nil, fmt.Errorf("no test endpoint at %s", addr)
	}
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func newEndpoint(t *testing.T, respond func(q dnsmessage.Question) reply) *testEndpoint {
	t.Helper()
	ep := &testEndpoint{}
	ep.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ep.hits.Add(1)
		body, err := io.ReadAll(r.Body)
		var q dnsmessage.Message
		if err != nil || r.Method != http.MethodPost ||
			r.Header.Get("Content-Type") != "application/dns-message" ||
			q.Unpack(body) != nil || len(q.Questions) != 1 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ep.mu.Lock()
		ep.lastQuery = body
		ep.mu.Unlock()

		rep := respond(q.Questions[0])
		if rep.status != 0 {
			http.Error(w, "unavailable", rep.status)
			return
		}
		resp, err := buildReply(q.ID, q.Questions[0], rep)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	}))
	_ = ep.Listener.Close()
	ep.Listener = newPipeListener()
	ep.StartTLS()
	t.Cleanup(ep.Close)
	return ep
}

func buildReply(id uint16, q dnsmessage.Question, rep reply) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: id, Response: true, RecursionDesired: true, RecursionAvailable: true,
		AuthenticData: rep.ad, RCode: rep.rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, ip := range rep.ips {
		h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 300}
		if v4 := ip.To4(); v4 != nil {
			if q.Type != dnsmessage.TypeA {
				continue
			}
			var a [4]byte
			copy(a[:], v4)
			if err := b.AResource(h, dnsmessage.AResource{A: a}); err != nil {
				return nil, err
			}
			continue
		}
		if q.Type != dnsmessage.TypeAAAA {
			continue
		}
		var aaaa [16]byte
		copy(aaaa[:], ip.To16())
		if err := b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: aaaa}); err != nil {
			return nil, err
		}
	}
	if rep.ede != 0 {
		if err := b.StartAdditionals(); err != nil {
			return nil, err
		}
		var opt dnsmessage.ResourceHeader
		if err := opt.SetEDNS0(ednsPayload, dnsmessage.RCodeSuccess, true); err != nil {
			return nil, err
		}
		ede := dnsmessage.Option{Code: optionEDE, Data: binary.BigEndian.AppendUint16(nil, rep.ede)}
		if err := b.OPTResource(opt, dnsmessage.OPTResource{Options: []dnsmessage.Option{ede}}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func newTestClient(t *testing.T, mode Mode, eps ...*testEndpoint) *Client {
	t.Helper()
	pool := x509.NewCertPool()
	var urls []string
	for _, ep := range eps {
		pool.AddCert(ep.Certificate())
		urls = append(urls, ep.URL+"/dns-query")
	}
	c, err := New(Options{Endpoints: urls, RootCAs: pool, Mode: mode, Dial: pipeDial})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

var (
	ip4 = net.ParseIP("192.0.2.1")
	ip6 = net.ParseIP("2001:db8::1")
)

func secure(q dnsmessage.Question) reply { return reply{ad: true, ips: []net.IP{ip6, ip4}} }

func TestBuildQuerySetsDNSSECOKAndPads(t *testing.T) {
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("example.org."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	for _, dnssecOK := range []bool{true, false} {
		wire, err := buildQuery(q, dnssecOK)
		if err != nil {
			t.Fatal(err)
		}
		if len(wire)%paddingBlock != 0 {
			t.Errorf("query length %d is not a multiple of %d", len(wire), paddingBlock)
		}
		var m dnsmessage.Message
		if err := m.Unpack(wire); err != nil {
			t.Fatal(err)
		}
		if m.ID != 0 || !m.RecursionDesired || len(m.Questions) != 1 {
			t.Errorf("unexpected header/question: %+v", m.Header)
		}
		var sawOPT, sawPadding bool
		for _, rr := range m.Additionals {
			opt, ok := rr.Body.(*dnsmessage.OPTResource)
			if !ok {
				continue
			}
			sawOPT = true
			if rr.Header.DNSSECAllowed() != dnssecOK {
				t.Errorf("DO bit = %v, want %v", rr.Header.DNSSECAllowed(), dnssecOK)
			}
			for _, o := range opt.Options {
				sawPadding = sawPadding || o.Code == optionPadding
			}
		}
		if !sawOPT || !sawPadding {
			t.Errorf("missing EDNS(0) OPT (%v) or padding option (%v)", sawOPT, sawPadding)
		}
	}
}

func TestLookupIPReturnsIPv4First(t *testing.T) {
	ep := newEndpoint(t, secure)
	ips, err := newTestClient(t, ModeValidate, ep).LookupIP(testCtx(t), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 || !ips[0].Equal(ip4) || !ips[1].Equal(ip6) {
		t.Fatalf("got %v, want [%v %v]", ips, ip4, ip6)
	}

	ep.mu.Lock()
	sent := ep.lastQuery
	ep.mu.Unlock()
	if len(sent)%paddingBlock != 0 {
		t.Errorf("sent query of %d bytes, not padded", len(sent))
	}
}

func TestBogusAnswerIsFinal(t *testing.T) {
	bogus := newEndpoint(t, func(dnsmessage.Question) reply {
		return reply{rcode: dnsmessage.RCodeServerFailure, ede: 6}
	})
	good := newEndpoint(t, secure)
	_, err := newTestClient(t, ModeValidate, bogus, good).LookupIP(testCtx(t), "example.org")
	if !errors.Is(err, ErrBogus) {
		t.Fatalf("got %v, want ErrBogus", err)
	}
	if n := good.hits.Load(); n != 0 {
		t.Errorf("fell back to the next endpoint %d times after a bogus answer", n)
	}
}

func TestTransportErrorsFallThrough(t *testing.T) {
	for name, rep := range map[string]reply{
		"http 503":        {status: http.StatusServiceUnavailable},
		"servfail no EDE": {rcode: dnsmessage.RCodeServerFailure},
		"servfail EDE 22": {rcode: dnsmessage.RCodeServerFailure, ede: 22}, // No Reachable Authority
		"refused":         {rcode: dnsmessage.RCodeRefused},
	} {
		t.Run(name, func(t *testing.T) {
			bad := newEndpoint(t, func(dnsmessage.Question) reply { return rep })
			good := newEndpoint(t, secure)
			ips, err := newTestClient(t, ModeValidate, bad, good).LookupIP(testCtx(t), "example.org")
			if err != nil || len(ips) != 2 {
				t.Fatalf("got %v, %v; want both addresses from the second endpoint", ips, err)
			}
		})
	}
}

func TestDNSSECModes(t *testing.T) {
	unauthenticated := func(dnsmessage.Question) reply { return reply{ips: []net.IP{ip4}} }
	cases := []struct {
		mode    Mode
		host    string
		wantErr error
	}{
		{ModeValidate, "example.org", nil},                      // unsigned zones are fine
		{ModeValidate, "api.cloudflareclient.com", ErrInsecure}, // but the WARP API zone is signed
		{ModeValidate, "API.CloudflareClient.com.", ErrInsecure},
		{ModeStrict, "example.org", ErrInsecure},
		{ModeOff, "api.cloudflareclient.com", nil},
	}
	for _, tc := range cases {
		ep := newEndpoint(t, unauthenticated)
		_, err := newTestClient(t, tc.mode, ep).LookupIP(testCtx(t), tc.host)
		if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
			t.Errorf("mode %d, %s: got %v, want %v", tc.mode, tc.host, err, tc.wantErr)
		}
	}
}

func TestNXDomain(t *testing.T) {
	ep := newEndpoint(t, func(dnsmessage.Question) reply { return reply{rcode: dnsmessage.RCodeNameError, ad: true} })
	_, err := newTestClient(t, ModeValidate, ep).LookupIP(testCtx(t), "missing.example.org")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("got %v, want a not-found *net.DNSError", err)
	}
}

func TestLookupIPIsCached(t *testing.T) {
	ep := newEndpoint(t, secure)
	c := newTestClient(t, ModeValidate, ep)
	for range 3 {
		if _, err := c.LookupIP(testCtx(t), "example.org"); err != nil {
			t.Fatal(err)
		}
	}
	if n := ep.hits.Load(); n != 2 { // one A and one AAAA query
		t.Errorf("endpoint hit %d times, want 2", n)
	}
}

func TestResolverAdapter(t *testing.T) {
	ep := newEndpoint(t, secure)
	ips, err := newTestClient(t, ModeValidate, ep).Resolver().LookupIP(testCtx(t), "ip4", "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(ip4) {
		t.Fatalf("got %v, want [%v]", ips, ip4)
	}

	bogus := newEndpoint(t, func(dnsmessage.Question) reply {
		return reply{rcode: dnsmessage.RCodeServerFailure, ede: 6}
	})
	if ips, err := newTestClient(t, ModeValidate, bogus).Resolver().LookupIP(testCtx(t), "ip4", "example.org"); err == nil {
		t.Fatalf("bogus answer resolved to %v", ips)
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeValidate, "validate": ModeValidate, "STRICT": ModeStrict, "off": ModeOff} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseMode("maybe"); err == nil {
		t.Error("ParseMode accepted an unknown mode")
	}
}

func TestNewRejectsNonHTTPSEndpoints(t *testing.T) {
	for _, ep := range []string{"http://1.1.1.1/dns-query", "1.1.1.1", "https://"} {
		if _, err := New(Options{Endpoints: []string{ep}}); err == nil {
			t.Errorf("New accepted endpoint %q", ep)
		}
	}
}

// TestLiveCloudflare talks to the real 1.1.1.1. Run with USQUE_LIVE_DOH=1.
func TestLiveCloudflare(t *testing.T) {
	if os.Getenv("USQUE_LIVE_DOH") == "" {
		t.Skip("set USQUE_LIVE_DOH=1 to query Cloudflare")
	}
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	ips, err := c.LookupIP(testCtx(t), "api.cloudflareclient.com")
	if err != nil || len(ips) == 0 {
		t.Fatalf("api.cloudflareclient.com: %v, %v", ips, err)
	}
	t.Logf("api.cloudflareclient.com -> %v (DNSSEC-authenticated)", ips)
	if _, err := c.LookupIP(testCtx(t), "dnssec-failed.org"); !errors.Is(err, ErrBogus) {
		t.Fatalf("dnssec-failed.org: got %v, want ErrBogus", err)
	}
}
