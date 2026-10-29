package usernet

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/seeker/uni-next/internal/network"
)

func TestLeaseEmitsTCPAsRawIPv4(t *testing.T) {
	vip := netip.MustParseAddr("10.23.0.2")
	destination := netip.MustParseAddr("10.23.1.10")
	lease := New(1300)
	plan := network.Plan{
		VIP:       vip,
		VIPPrefix: netip.MustParsePrefix("10.23.0.2/24"),
		Routes:    []netip.Prefix{netip.PrefixFrom(destination, 32)},
	}
	if err := lease.Activate(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	egress, err := lease.Egress()
	if err != nil {
		t.Fatal(err)
	}
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDial()
	dialDone := make(chan error, 1)
	go func() {
		connection, err := egress.DialTCP(dialCtx, netip.AddrPortFrom(destination, 443))
		if connection != nil {
			connection.Close()
		}
		dialDone <- err
	}()

	readCtx, cancelRead := context.WithTimeout(context.Background(), time.Second)
	defer cancelRead()
	packet := make([]byte, 1300)
	count, err := lease.ReadContext(readCtx, packet)
	if err != nil {
		t.Fatal(err)
	}
	packet = packet[:count]
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 6 {
		t.Fatalf("not a TCP/IPv4 packet: %x", packet)
	}
	source, ok := netip.AddrFromSlice(packet[12:16])
	if !ok || source != vip {
		t.Fatalf("source=%v, want %v", source, vip)
	}
	target, ok := netip.AddrFromSlice(packet[16:20])
	if !ok || target != destination {
		t.Fatalf("destination=%v, want %v", target, destination)
	}
	cancelDial()
	select {
	case <-dialDone:
	case <-time.After(time.Second):
		t.Fatal("userspace TCP dial did not cancel")
	}
}

func TestLeaseEmitsUDPAsRawIPv4(t *testing.T) {
	vip := netip.MustParseAddr("10.23.0.2")
	destination := netip.MustParseAddr("10.23.1.10")
	lease := New(1300)
	plan := network.Plan{
		VIP:       vip,
		VIPPrefix: netip.MustParsePrefix("10.23.0.2/24"),
		Routes:    []netip.Prefix{netip.PrefixFrom(destination, 32)},
	}
	if err := lease.Activate(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	egress, err := lease.Egress()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := egress.ListenUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.WriteTo([]byte("hello"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(destination, 53))); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	packet := make([]byte, 1300)
	count, err := lease.ReadContext(ctx, packet)
	if err != nil {
		t.Fatal(err)
	}
	packet = packet[:count]
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 17 {
		t.Fatalf("not a UDP/IPv4 packet: %x", packet)
	}
	source, ok := netip.AddrFromSlice(packet[12:16])
	if !ok || source != vip {
		t.Fatalf("source=%v, want %v", source, vip)
	}
	target, ok := netip.AddrFromSlice(packet[16:20])
	if !ok || target != destination {
		t.Fatalf("destination=%v, want %v", target, destination)
	}
}
