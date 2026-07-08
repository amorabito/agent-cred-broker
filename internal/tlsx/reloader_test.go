package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSigned writes a fresh self-signed cert/key pair to certFile/keyFile
// and returns the leaf's serial so a caller can tell two generations apart.
func writeSelfSigned(t *testing.T, certFile, keyFile string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReloaderPicksUpRotation(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")
	writeSelfSigned(t, cert, key, 1)

	r := &Reloader{CertFile: cert, KeyFile: key}
	cfg, err := r.Config()
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if cfg.GetCertificate == nil {
		t.Fatal("Config must serve via GetCertificate")
	}
	c1, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	first := c1.Leaf
	if first == nil {
		var perr error
		first, perr = x509.ParseCertificate(c1.Certificate[0])
		if perr != nil {
			t.Fatal(perr)
		}
	}

	// Rotate with an mtime strictly in the future so the mtime check fires
	// regardless of filesystem timestamp granularity.
	writeSelfSigned(t, cert, key, 2)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(cert, future, future); err != nil {
		t.Fatal(err)
	}
	c2, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := x509.ParseCertificate(c2.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if second.SerialNumber.Int64() != 2 {
		t.Fatalf("expected rotated cert serial 2, got %d", second.SerialNumber.Int64())
	}
}

func TestReloaderServesLastGoodOnReadError(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")
	writeSelfSigned(t, cert, key, 7)

	r := &Reloader{CertFile: cert, KeyFile: key}
	if _, err := r.Config(); err != nil {
		t.Fatal(err)
	}
	// Cert file vanishes mid-flight (a partial cert-manager write): serve the
	// last-good cert, never a handshake-fatal error.
	if err := os.Remove(cert); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("expected last-good cert, got error %v", err)
	}
	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.Int64() != 7 {
		t.Fatalf("expected last-good serial 7, got %d", leaf.SerialNumber.Int64())
	}
}

func TestReloaderConfigFailsFastOnBadPath(t *testing.T) {
	r := &Reloader{CertFile: "/nonexistent/tls.crt", KeyFile: "/nonexistent/tls.key"}
	if _, err := r.Config(); err == nil {
		t.Fatal("expected Config to fail on unreadable keypair")
	}
}
