//go:build android

package trust

import (
	"crypto/x509"
	"log"
	"os"
	"path/filepath"
)

// Android apps ignore user-installed CAs by default (API 24+), but Go's crypto/x509
// on Android also loads /data/misc/keychain/certs-added. Anything that can get a CA
// into that store (an MDM profile, a "security" app, a coerced user) could then
// intercept registration -- which is where the tunnel's pinned endpoint key comes
// from -- and DNS-over-HTTPS. So only the system stores are loaded here.
var systemDirs = []string{
	"/apex/com.android.conscrypt/cacerts", // Android 14+, updated through Play
	"/system/etc/security/cacerts",
}

func load() *x509.CertPool {
	pool := x509.NewCertPool()
	loaded := 0
	for _, dir := range systemDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			if pool.AppendCertsFromPEM(data) {
				loaded++
			}
		}
	}
	if loaded == 0 {
		log.Println("trust: no system CA certificates readable; falling back to Go's default roots")
		return nil
	}
	return pool
}
