package doh

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Resolver returns a *net.Resolver that answers every query through this client, for
// callers (including the standard library's dialer) that only know net.Resolver.
func (c *Client) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return &streamConn{ctx: ctx, client: c}, nil
		},
	}
}

// streamConn hands the Go resolver a connection that speaks DNS-over-TCP framing
// (RFC 1035 §4.2.2), which it uses for any Conn that is not a net.PacketConn, and
// answers each query with a DoH round trip.
type streamConn struct {
	ctx    context.Context
	client *Client

	mu  sync.Mutex
	in  []byte
	out bytes.Buffer
}

func (s *streamConn) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.in = append(s.in, b...)
	for len(s.in) >= 2 {
		n := int(binary.BigEndian.Uint16(s.in))
		if len(s.in) < 2+n {
			break
		}
		resp := s.client.answer(s.ctx, s.in[2:2+n])
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(resp)))
		_, _ = s.out.Write(length[:])
		_, _ = s.out.Write(resp)
		s.in = s.in[2+n:]
	}
	return len(b), nil
}

func (s *streamConn) Read(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.out.Len() == 0 {
		return 0, io.EOF
	}
	return s.out.Read(b)
}

func (s *streamConn) Close() error                     { return nil }
func (s *streamConn) LocalAddr() net.Addr              { return dohAddr{} }
func (s *streamConn) RemoteAddr() net.Addr             { return dohAddr{} }
func (s *streamConn) SetDeadline(time.Time) error      { return nil }
func (s *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (s *streamConn) SetWriteDeadline(time.Time) error { return nil }

type dohAddr struct{}

func (dohAddr) Network() string { return "doh" }
func (dohAddr) String() string  { return "doh" }

// answer resolves one wire-format query from the Go resolver and returns the response
// under the query's own ID. Any failure, DNSSEC ones included, becomes SERVFAIL so the
// Go resolver reports an error instead of trusting anything.
func (c *Client) answer(ctx context.Context, query []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return servfail(h, nil)
	}
	_, raw, err := c.exchange(ctx, q)
	if err != nil {
		return servfail(h, &q)
	}
	binary.BigEndian.PutUint16(raw, h.ID)
	return raw
}

func servfail(h dnsmessage.Header, q *dnsmessage.Question) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeServerFailure,
	})
	if q != nil {
		if b.StartQuestions() != nil || b.Question(*q) != nil {
			return nil
		}
	}
	msg, err := b.Finish()
	if err != nil {
		return nil
	}
	return msg
}
