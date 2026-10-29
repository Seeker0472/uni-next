package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/seeker/uni-next/internal/config"
	genstate "github.com/seeker/uni-next/internal/generation"
)

func TestServerRelaysAuthorizedTCPAndUDP(t *testing.T) {
	host := nonLoopbackIPv4(t)
	prefix := netip.PrefixFrom(host, 32)
	tcpTarget, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(host.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	defer tcpTarget.Close()
	go func() {
		connection, err := tcpTarget.Accept()
		if err == nil {
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}
	}()
	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(host.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			count, source, err := udpTarget.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = udpTarget.WriteToUDP(buffer[:count], source)
		}
	}()
	listenerPort := freeTCPPort(t)
	relayPort := freeUDPPort(t)
	cfg := config.Defaults()
	cfg.Network.AllowedRoutes = []string{prefix.String()}
	cfg.Socks.Enabled = true
	cfg.Socks.Listeners = []string{net.JoinHostPort("127.0.0.1", itoa(listenerPort))}
	cfg.Socks.Auth.Username = "proxy"
	cfg.Socks.AllowSources = []string{"127.0.0.1/32"}
	cfg.Socks.AllowedDestinations = []string{prefix.String()}
	cfg.Socks.UDP.PortRange = config.PortRange{From: uint16(relayPort), To: uint16(relayPort)}
	cfg.Socks.UDP.MaxAssociations = 1
	gate := &genstate.Gate{}
	generationCtx, generationCancel := context.WithCancel(context.Background())
	defer generationCancel()
	gate.Set(genstate.Generation{ID: 1, Context: generationCtx, VIP: host, Routes: []netip.Prefix{prefix}, Interface: "test", Egress: testEgress{host: host}})
	server, err := New(cfg, []byte("secret"), gate)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	address := cfg.Socks.Listeners[0]

	tcpClient := dialSOCKS(t, address)
	defer tcpClient.Close()
	authenticateSOCKS(t, tcpClient)
	target := tcpTarget.Addr().(*net.TCPAddr).AddrPort()
	writeRequest(t, tcpClient, commandConnect, target)
	readSuccessReply(t, tcpClient)
	payload := []byte("tcp-through-socks")
	if _, err := tcpClient.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(tcpClient, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("TCP reply=%q", reply)
	}

	control := dialSOCKS(t, address)
	defer control.Close()
	authenticateSOCKS(t, control)
	writeRequest(t, control, commandUDPAssociate, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	relay := readSuccessReply(t, control)
	udpClient, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	udpPayload := []byte("udp-through-socks")
	target = udpTarget.LocalAddr().(*net.UDPAddr).AddrPort()
	packet := udpPacket(target, udpPayload)
	if _, err := udpClient.WriteToUDPAddrPort(packet, relay); err != nil {
		t.Fatal(err)
	}
	_ = udpClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 2048)
	count, _, err := udpClient.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	source, response, err := parseUDPRequest(buffer[:count])
	if err != nil {
		t.Fatal(err)
	}
	if source.host != target.Addr().String() || source.port != target.Port() || string(response) != string(udpPayload) {
		t.Fatalf("unexpected UDP response source=%#v payload=%q", source, response)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS server did not stop")
	}
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

type testEgress struct {
	host netip.Addr
}

func (e testEgress) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(e.host.AsSlice())}}
	return dialer.DialContext(ctx, "tcp4", destination.String())
}

func (e testEgress) ListenUDP() (net.PacketConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(e.host.AsSlice())})
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
func freeUDPPort(t *testing.T) int {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	return connection.LocalAddr().(*net.UDPAddr).Port
}
func itoa(value int) string { return strconv.Itoa(value) }
func dialSOCKS(t *testing.T, address string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp4", address, 200*time.Millisecond)
		if err == nil {
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			return connection
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func authenticateSOCKS(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := writeFull(connection, []byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(connection, method); err != nil {
		t.Fatal(err)
	}
	if method[1] != 2 {
		t.Fatalf("method=%v", method)
	}
	request := append([]byte{1, 5}, []byte("proxy")...)
	request = append(request, 6)
	request = append(request, []byte("secret")...)
	if err := writeFull(connection, request); err != nil {
		t.Fatal(err)
	}
	status := make([]byte, 2)
	if _, err := io.ReadFull(connection, status); err != nil {
		t.Fatal(err)
	}
	if status[1] != 0 {
		t.Fatalf("auth status=%v", status)
	}
}
func writeRequest(t *testing.T, connection net.Conn, command byte, target netip.AddrPort) {
	t.Helper()
	packet := make([]byte, 10)
	packet[0] = 5
	packet[1] = command
	packet[3] = 1
	copy(packet[4:8], target.Addr().AsSlice())
	binary.BigEndian.PutUint16(packet[8:10], target.Port())
	if _, err := connection.Write(packet); err != nil {
		t.Fatal(err)
	}
}
func readSuccessReply(t *testing.T, connection net.Conn) netip.AddrPort {
	t.Helper()
	packet := make([]byte, 10)
	if _, err := io.ReadFull(connection, packet); err != nil {
		t.Fatal(err)
	}
	if packet[0] != 5 || packet[1] != 0 || packet[3] != 1 {
		t.Fatalf("reply=%v", packet)
	}
	var raw [4]byte
	copy(raw[:], packet[4:8])
	return netip.AddrPortFrom(netip.AddrFrom4(raw), binary.BigEndian.Uint16(packet[8:10]))
}
func udpPacket(target netip.AddrPort, payload []byte) []byte {
	packet := make([]byte, 10+len(payload))
	packet[3] = 1
	copy(packet[4:8], target.Addr().AsSlice())
	binary.BigEndian.PutUint16(packet[8:10], target.Port())
	copy(packet[10:], payload)
	return packet
}
