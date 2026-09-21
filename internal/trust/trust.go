// Package trust builds the certificate pool usque uses for its own TLS clients: the
// WARP registration API and DNS-over-HTTPS. The MASQUE tunnel itself does not use it;
// that connection is pinned to the endpoint key saved at registration.
package trust

import (
	"crypto/x509"
	"sync"
)

var roots = sync.OnceValue(load)

// Roots returns the CA pool for usque's TLS clients. A nil pool means Go's default
// system roots. See the platform files for what each OS loads.
func Roots() *x509.CertPool {
	return roots()
}
