package univpn

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/seeker/uni-next/internal/config"
	"github.com/seeker/uni-next/internal/transport"
)

func TestClientCompletesVerifiedLocalProtocolExchange(t *testing.T) {
	certificate, parsed := localCertificate(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}})
	defer tlsListener.Close()
	sid := SessionID{9, 8, 7, 6}
	codec := NewCodec()
	serverErr := make(chan error, 1)
	handlers := []func(net.Conn) error{
		func(connection net.Conn) error {
			request, err := codec.Read(connection, nil)
			if err != nil {
				return err
			}
			if request.Type != 0x1d || len(request.Body) != 324 {
				return errors.New("bad first connect")
			}
			return codec.Write(connection, Frame{Session: SessionID{0, 0xff, 0xff, 0xff}, Type: 0x1d, Body: make([]byte, 776)})
		},
		func(connection net.Conn) error {
			reader := bufio.NewReader(connection)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return err
				}
				if line == "\r\n" {
					break
				}
			}
			response := syntheticAuthResponse()
			copy(response[4:8], sid[:])
			copy(response[0x2c:0x30], sid[:])
			_, err := connection.Write(response)
			return err
		},
		func(connection net.Conn) error {
			request, err := codec.Read(connection, &sid)
			if err != nil {
				return err
			}
			if request.Type != 6 {
				return errors.New("bad ACL request")
			}
			aclBody := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1}
			var acl bytes.Buffer
			if err := codec.Write(&acl, Frame{Session: sid, Type: 6, Body: aclBody}); err != nil {
				return err
			}
			raw := acl.Bytes()
			raw[14] = 0x14
			raw[15] = 0
			if _, err := connection.Write(raw); err != nil {
				return err
			}
			request, err = codec.Read(connection, &sid)
			if err != nil {
				return err
			}
			if request.Type != 3 {
				return errors.New("bad netcfg request")
			}
			if err := codec.Write(connection, Frame{Session: sid, Type: 3, Body: syntheticNetConfig()}); err != nil {
				return err
			}
			request, err = codec.Read(connection, &sid)
			if err != nil {
				return err
			}
			if request.Type != 0x0d {
				return errors.New("bad key request")
			}
			key := make([]byte, 20)
			key[3] = 3
			if err := codec.Write(connection, Frame{Session: sid, Type: 0x0d, Body: key}); err != nil {
				return err
			}
			request, err = codec.Read(connection, &sid)
			if err != nil {
				return err
			}
			if request.Type != 0x1a {
				return errors.New("bad port request")
			}
			if err := codec.Write(connection, Frame{Session: sid, Type: 0x1a, Body: []byte{0x24, 0xe3, 0, 0}}); err != nil {
				return err
			}
			request, err = codec.Read(connection, &sid)
			if err != nil {
				return err
			}
			if request.Type != 0x10 {
				return errors.New("bad SSL switch")
			}
			request, err = codec.Read(connection, &sid)
			if err != nil {
				return err
			}
			if request.Type != TypeKeepalive {
				return errors.New("bad keepalive")
			}
			return codec.Write(connection, Frame{Session: sid, Type: TypeKeepalive})
		},
		func(connection net.Conn) error {
			reader := bufio.NewReader(connection)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return err
				}
				if line == "\r\n" {
					break
				}
			}
			_, err := connection.Write([]byte("HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n"))
			return err
		},
	}
	go func() {
		for _, handler := range handlers {
			connection, err := tlsListener.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			err = handler(connection)
			connection.Close()
			if err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	cfg := config.Defaults()
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.Port = uint16(port)
	cfg.Auth.Username = "user"
	cfg.Auth.MAC = "02:00:00:00:00:01"
	cfg.Network.AllowedRoutes = []string{"10.19.20.0/24"}
	cfg.TLS.SPKIPinFile = ""
	digest := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	cfg.TLS.SPKISHA256 = []string{base64.StdEncoding.EncodeToString(digest[:])}
	cfg.TLS.CipherSuites = []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
	cfg.Timeouts.Connect = config.D(2 * time.Second)
	cfg.Timeouts.TLS = config.D(2 * time.Second)
	cfg.Timeouts.Auth = config.D(2 * time.Second)
	cfg.Timeouts.ControlStep = config.D(2 * time.Second)
	cfg.Timeouts.Logout = config.D(2 * time.Second)
	dialer, err := transport.NewDialer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(cfg, dialer.Dial)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.FirstConnect(ctx); err != nil {
		t.Fatal(err)
	}
	auth, err := client.Authenticate(ctx, Identity{Username: "user", Password: []byte("p&a ss"), MAC: cfg.Auth.MAC})
	if err != nil {
		t.Fatal(err)
	}
	negotiated, err := client.Negotiate(ctx, auth)
	if err != nil {
		t.Fatal(err)
	}
	if negotiated.UDPPort != 9443 || len(negotiated.Network.Routes) != 1 {
		t.Fatalf("unexpected negotiation: %#v", negotiated)
	}
	if err := codec.Write(negotiated.Connection, Frame{Session: auth.Session, Type: TypeKeepalive}); err != nil {
		t.Fatal(err)
	}
	frame, err := codec.Read(negotiated.Connection, &auth.Session)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != TypeKeepalive {
		t.Fatal("missing keepalive response")
	}
	negotiated.Connection.Close()
	if err := client.Logout(ctx, auth, []byte("12345")); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func localCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "no-san"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key}, parsed
}
