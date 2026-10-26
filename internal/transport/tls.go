// Package transport provides the current profile's pinned TLS 1.2 transport.
package transport

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/seeker/univpn/internal/apperr"
	"github.com/seeker/univpn/internal/config"
)

type Dialer struct {
	address        string
	connectTimeout time.Duration
	tlsTimeout     time.Duration
	config         *tls.Config
}

func NewDialer(cfg config.Config) (*Dialer, error) {
	pins, err := loadPins(cfg.TLS)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeConfig, "tls", apperr.RetryNever, "invalid SPKI pin configuration", err)
	}
	cipherSuites, err := config.CipherSuiteIDs(cfg.TLS.CipherSuites)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeConfig, "tls", apperr.RetryNever, "invalid cipher suite configuration", err)
	}
	tlsConfig := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12,
		CipherSuites:           cipherSuites,
		InsecureSkipVerify:     true, // Required because this profile's pinned certificate has no SAN.
		VerifyConnection:       verifyPinnedConnection(pins),
		SessionTicketsDisabled: true,
	}
	return &Dialer{
		address:        net.JoinHostPort(cfg.Server.Host, fmt.Sprintf("%d", cfg.Server.Port)),
		connectTimeout: cfg.Timeouts.Connect.Duration,
		tlsTimeout:     cfg.Timeouts.TLS.Duration,
		config:         tlsConfig,
	}, nil
}

func (d *Dialer) Dial(ctx context.Context) (net.Conn, error) {
	tcpDialer := &net.Dialer{Timeout: d.connectTimeout, KeepAlive: 30 * time.Second}
	raw, err := tcpDialer.DialContext(ctx, "tcp4", d.address)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeTransient, "tcp_connect", apperr.RetryNetwork, "gateway connection failed", err)
	}
	connection := tls.Client(raw, d.config.Clone())
	handshakeCtx, cancel := context.WithTimeout(ctx, d.tlsTimeout)
	defer cancel()
	if err := connection.HandshakeContext(handshakeCtx); err != nil {
		raw.Close()
		var appErr *apperr.Error
		if errors.As(err, &appErr) {
			return nil, err
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, apperr.Wrap(apperr.CodeTransient, "tls_handshake", apperr.RetryNetwork, "TLS handshake was interrupted", err)
		}
		var networkError net.Error
		if errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary()) {
			return nil, apperr.Wrap(apperr.CodeTransient, "tls_handshake", apperr.RetryNetwork, "TLS handshake failed because of a network error", err)
		}
		return nil, apperr.Wrap(apperr.CodeTrust, "tls_handshake", apperr.RetryNever, "TLS handshake or pinned certificate verification failed", err)
	}
	return connection, nil
}

func verifyPinnedConnection(pins [][32]byte) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS12 {
			return apperr.New(apperr.CodeTrust, "tls_verify", apperr.RetryNever, "gateway did not negotiate TLS 1.2")
		}
		if len(state.PeerCertificates) == 0 {
			return apperr.New(apperr.CodeTrust, "tls_verify", apperr.RetryNever, "gateway provided no certificate")
		}
		leaf := state.PeerCertificates[0]
		now := time.Now()
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return apperr.New(apperr.CodeTrust, "tls_verify", apperr.RetryNever, "gateway certificate is outside its validity period")
		}
		if !allowsServerAuth(leaf) {
			return apperr.New(apperr.CodeTrust, "tls_verify", apperr.RetryNever, "gateway certificate does not permit server authentication")
		}
		key, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 2048 {
			return apperr.New(apperr.CodeTrust, "tls_verify", apperr.RetryNever, "gateway certificate must use RSA with at least 2048 bits")
		}
		digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		matched := 0
		for _, pin := range pins {
			matched |= subtle.ConstantTimeCompare(digest[:], pin[:])
		}
		if matched != 1 {
			return apperr.New(apperr.CodeTrust, "tls_verify", apperr.RetryNever, "gateway public key does not match a configured pin")
		}
		return nil
	}
}

func allowsServerAuth(certificate *x509.Certificate) bool {
	if len(certificate.ExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func loadPins(cfg config.TLS) ([][32]byte, error) {
	values := append([]string(nil), cfg.SPKISHA256...)
	if cfg.SPKIPinFile != "" {
		file, err := os.Open(cfg.SPKIPinFile)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 1024), 64<<10)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				values = append(values, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	if len(values) == 0 {
		return nil, errors.New("no SPKI pins configured")
	}
	pins := make([][32]byte, 0, len(values))
	seen := make(map[[32]byte]struct{})
	for _, value := range values {
		pin, err := config.ParsePin(value)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[pin]; duplicate {
			return nil, errors.New("duplicate SPKI pin")
		}
		seen[pin] = struct{}{}
		pins = append(pins, pin)
	}
	return pins, nil
}
