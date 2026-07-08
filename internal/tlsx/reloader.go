// Package tlsx holds small TLS serving helpers shared by the broker and the
// notify proxy.
package tlsx

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// Reloader serves a TLS keypair via tls.Config.GetCertificate, re-reading it
// from disk when the cert file's mtime advances. cert-manager rotates the
// serving cert (~15 days before a 90-day expiry) by rewriting the mounted
// files; without this a long-running pod keeps serving the old cert until it
// restarts, and a pod that outlives the cert would fail every TLS handshake.
// A transient read error serves the last-good cert rather than dropping TLS.
type Reloader struct {
	CertFile, KeyFile string

	mu   sync.Mutex
	cert *tls.Certificate
	mod  time.Time
}

// GetCertificate is the tls.Config.GetCertificate callback.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fi, err := os.Stat(r.CertFile)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil
		}
		return nil, err
	}
	if r.cert != nil && !fi.ModTime().After(r.mod) {
		return r.cert, nil
	}
	pair, err := tls.LoadX509KeyPair(r.CertFile, r.KeyFile)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil
		}
		return nil, err
	}
	r.cert, r.mod = &pair, fi.ModTime()
	return r.cert, nil
}

// Config returns a *tls.Config that serves via the reloader, after eagerly
// loading the keypair once so a bad path fails fast at startup.
func (r *Reloader) Config() (*tls.Config, error) {
	if _, err := r.GetCertificate(nil); err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: r.GetCertificate}, nil
}
