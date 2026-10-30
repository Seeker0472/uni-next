//go:build linux

package linux

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/seeker/uni-next/internal/config"
	"github.com/seeker/uni-next/internal/network"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestLeaseLifecycleInIsolatedNamespace(t *testing.T) {
	if os.Getenv("UNI_NEXT_TEST_NET_ADMIN") != "1" {
		t.Skip("set UNI_NEXT_TEST_NET_ADMIN=1 only inside an isolated network namespace")
	}
	if os.Geteuid() != 0 {
		t.Skip("isolated network lifecycle test requires root")
	}

	cfg := config.Defaults()
	cfg.Runtime.StateDir = t.TempDir()
	cfg.Network.TunName = fmt.Sprintf("uvpn%d", os.Getpid()%100000)
	cfg.Network.Table = 20000 + os.Getpid()%1000
	cfg.Network.RulePriority = 20000 + os.Getpid()%1000
	protected := netip.MustParsePrefix("203.0.113.0/24")
	active := protected
	vip := netip.MustParseAddr("10.98.0.2")

	lease, err := Prepare(context.Background(), cfg, []netip.Prefix{protected})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = lease.Close()
		}
	})

	if _, err := netlink.LinkByName(cfg.Network.TunName); err != nil {
		t.Fatalf("prepared TUN is absent: %v", err)
	}
	assertRoute(t, cfg.Network.Table, protected, unix.RTN_UNREACHABLE, true)

	plan := network.Plan{
		VIP:       vip,
		VIPPrefix: netip.PrefixFrom(vip, 32),
		Routes:    []netip.Prefix{active},
		Protected: []netip.Prefix{protected},
	}
	if err := lease.Activate(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	assertRoute(t, cfg.Network.Table, active, unix.RTN_UNICAST, true)
	verifyTunRead(t, lease, netip.MustParseAddr("203.0.113.1"))

	if err := lease.Suspend(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertRoute(t, cfg.Network.Table, active, unix.RTN_UNICAST, false)
	assertRoute(t, cfg.Network.Table, protected, unix.RTN_UNREACHABLE, true)

	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	if _, err := netlink.LinkByName(cfg.Network.TunName); err == nil {
		t.Fatal("owned TUN remained after close")
	}
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: cfg.Network.TunName}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(dummy)
	if _, err := Prepare(context.Background(), cfg, []netip.Prefix{protected}); err == nil {
		t.Fatal("prepare attached to a pre-existing interface")
	}
	if _, err := netlink.LinkByName(cfg.Network.TunName); err != nil {
		t.Fatalf("failed prepare removed an unowned interface: %v", err)
	}
	assertRoute(t, cfg.Network.Table, protected, unix.RTN_UNREACHABLE, false)
}

func verifyTunRead(t *testing.T, lease network.Lease, destination netip.Addr) {
	t.Helper()
	connection, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(destination, 9)))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("uni-next TUN read probe")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	buffer := make([]byte, cfgTestMTU)
	for {
		count, err := lease.Device().ReadContext(ctx, buffer)
		if err != nil {
			t.Fatalf("read outbound TUN packet: %v", err)
		}
		if count >= 20 && buffer[0]>>4 == 4 {
			return
		}
	}
}

const cfgTestMTU = 1300

func assertRoute(t *testing.T, table int, prefix netip.Prefix, routeType int, want bool) {
	t.Helper()
	destination := ipNet(prefix)
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: table, Dst: destination}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, route := range routes {
		if route.Type == routeType {
			found = true
			break
		}
	}
	if found != want {
		t.Fatalf("route %s type %d presence=%t, want %t; routes=%v", prefix, routeType, found, want, routes)
	}
}
