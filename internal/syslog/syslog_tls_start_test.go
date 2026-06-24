package syslog

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSignedCert generates a throwaway cert/key pair and returns their
// file paths, so LoadX509KeyPair succeeds and Start() proceeds to tls.Listen.
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "syslog-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// TestStart_TLSListenFailure_ReturnsError is the regression for the 2026-06-23
// CTO-loop H5 finding: in the UseTLS path, `cert, err := tls.LoadX509KeyPair(...)`
// declared a NEW err scoped to the if-block, so the subsequent
// `s.listener, err = tls.Listen(...)` wrote that shadow and the outer err
// (checked after the block) stayed nil. Start() then returned success and logged
// "started" while s.listener was nil — and acceptLoop nil-dereferenced
// s.listener.Accept() in an unrecovered goroutine, crashing the process.
//
// Here the cert loads fine but the port is already bound, so tls.Listen fails.
// A correct Start() must surface that as a non-nil error and must NOT start the
// accept loop.
func TestStart_TLSListenFailure_ReturnsError(t *testing.T) {
	// Occupy a port for the duration of the test.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port

	certPath, keyPath := writeSelfSignedCert(t)

	r := NewSyslogReceiver(&Config{
		ListenAddr: "127.0.0.1",
		Port:       port,
		UseTLS:     true,
		CertFile:   certPath,
		KeyFile:    keyPath,
	}, nil)

	err = r.Start()
	if err == nil {
		// Don't leak: if the bug regressed, Start lied about success.
		_ = r.Stop()
		t.Fatal("Start() returned nil on a failed TLS listen (occupied port); the outer err was shadowed and the listener is nil")
	}
	if r.running.Load() {
		t.Error("running flag set despite a failed Start()")
	}
}
