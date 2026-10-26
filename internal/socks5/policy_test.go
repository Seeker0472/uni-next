package socks5

import (
	"net/netip"
	"testing"
)

func TestDestinationRequiresConfiguredAndActiveRoute(t *testing.T) {
	server := &Server{allowedDestinations: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	active := []netip.Prefix{netip.MustParsePrefix("10.20.10.0/24")}
	if !server.destinationAllowed(netip.MustParseAddr("10.20.10.8"), active) {
		t.Fatal("destination inside both policies was rejected")
	}
	for _, denied := range []netip.Addr{
		netip.MustParseAddr("10.20.11.8"),
		netip.MustParseAddr("10.21.10.8"),
		netip.MustParseAddr("127.0.0.1"),
	} {
		if server.destinationAllowed(denied, active) {
			t.Fatalf("destination %s escaped policy intersection", denied)
		}
	}
}
