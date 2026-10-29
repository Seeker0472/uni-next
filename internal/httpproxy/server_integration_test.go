package httpproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/seeker/uni-next/internal/config"
	genstate "github.com/seeker/uni-next/internal/generation"
)

func TestServerForwardsHTTPAndCONNECT(t *testing.T) {
	host := nonLoopbackIPv4(t)
	prefix := netip.PrefixFrom(host, 32)

	httpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(host.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	defer httpListener.Close()
	targetHTTP := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "plain:"+request.URL.Path)
	})}
	defer targetHTTP.Close()
	go func() { _ = targetHTTP.Serve(httpListener) }()

	echoListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(host.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	go func() {
		connection, err := echoListener.Accept()
		if err == nil {
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}
	}()

	proxyPort := freeTCPPort(t)
	cfg := config.Defaults()
	cfg.Network.AllowedRoutes = []string{prefix.String()}
	cfg.HTTP.Enabled = true
	cfg.HTTP.Listeners = []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))}
	gate := &genstate.Gate{}
	generationCtx, generationCancel := context.WithCancel(context.Background())
	defer generationCancel()
	gate.Set(genstate.Generation{
		ID:      1,
		Context: generationCtx,
		VIP:     host,
		Routes:  []netip.Prefix{prefix},
		Egress:  hostEgress{host: host},
	})
	server, err := New(cfg, gate)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	proxyAddress := cfg.HTTP.Listeners[0]
	waitForListener(t, proxyAddress)

	proxyURL, err := url.Parse("http://" + proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}}
	response, err := client.Get("http://" + httpListener.Addr().String() + "/resource")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "plain:/resource" {
		t.Fatalf("unexpected HTTP response status=%d body=%q", response.StatusCode, body)
	}

	connection, err := net.DialTimeout("tcp4", proxyAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	target := echoListener.Addr().String()
	if _, err := fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, " 200 ") {
		t.Fatalf("CONNECT status=%q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	payload := []byte("through-connect")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("CONNECT reply=%q", reply)
	}
	if err := connection.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("CONNECT did not relay upstream EOF after client half-close: %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP proxy did not stop")
	}
}

type hostEgress struct {
	host netip.Addr
}

func (e hostEgress) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(e.host.AsSlice())}}
	return dialer.DialContext(ctx, "tcp4", destination.String())
}

func (e hostEgress) ListenUDP() (net.PacketConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(e.host.AsSlice())})
}

func nonLoopbackIPv4(t *testing.T) netip.Addr {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addresses {
			prefix, err := netip.ParsePrefix(raw.String())
			if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() {
				return prefix.Addr()
			}
		}
	}
	t.Skip("no non-loopback IPv4 address")
	return netip.Addr{}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
