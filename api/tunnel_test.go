package api

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestOversizeLogRateLimit(t *testing.T) {
	var out bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&out)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	var o oversizeLog
	o.note(1280)
	o.note(1280)
	o.note(1281)
	if got := strings.Count(out.String(), "\n"); got != 1 {
		t.Fatalf("logged %d lines within one interval, want 1:\n%s", got, out.String())
	}
	if want := "Dropped 1 tunnel packet(s) too large for a QUIC datagram (latest: 1280 bytes)"; !strings.Contains(out.String(), want) {
		t.Fatalf("first line %q does not contain %q", out.String(), want)
	}

	o.last = time.Now().Add(-oversizeLogInterval)
	out.Reset()
	o.note(1300)
	if want := "Dropped 3 tunnel packet(s) too large for a QUIC datagram (latest: 1300 bytes)"; !strings.Contains(out.String(), want) {
		t.Fatalf("second line %q does not contain %q", out.String(), want)
	}
}
