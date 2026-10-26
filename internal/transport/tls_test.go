package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"crypto/tls"
)

func testCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestVerifyPinnedConnection(t *testing.T) {
	certificate := testCertificate(t)
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	state := tls.ConnectionState{Version: tls.VersionTLS12, PeerCertificates: []*x509.Certificate{certificate}}
	if err := verifyPinnedConnection([][32]byte{pin})(state); err != nil {
		t.Fatal(err)
	}
	wrong := pin
	wrong[0] ^= 0xff
	if err := verifyPinnedConnection([][32]byte{wrong})(state); err == nil {
		t.Fatal("wrong pin was accepted")
	}
	state.Version = tls.VersionTLS13
	if err := verifyPinnedConnection([][32]byte{pin})(state); err == nil {
		t.Fatal("TLS 1.3 was accepted for current profile")
	}
	state.Version = tls.VersionTLS12
	certificate.NotAfter = time.Now().Add(-time.Second)
	if err := verifyPinnedConnection([][32]byte{pin})(state); err == nil {
		t.Fatal("expired certificate was accepted")
	}
}
