//go:build !android

package trust

import "crypto/x509"

// Elsewhere the system store is administered by whoever owns the machine, so Go's
// default roots (the platform verifier on Windows and macOS) are used as-is.
func load() *x509.CertPool {
	return nil
}
