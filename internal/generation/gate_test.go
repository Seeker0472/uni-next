package generation

import (
	"context"
	"net/netip"
	"testing"
)

func TestGateRejectsOldGenerationAndCopiesRoutes(t *testing.T) {
	gate := &Gate{}
	if _, err := gate.Acquire(); err == nil {
		t.Fatal("empty gate must reject")
	}
	ctx, cancel := context.WithCancel(context.Background())
	routes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	gate.Set(Generation{ID: 1, Context: ctx, VIP: netip.MustParseAddr("10.1.1.1"), Routes: routes})
	routes[0] = netip.MustParsePrefix("192.0.2.0/24")
	value, err := gate.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if value.Routes[0].String() != "10.0.0.0/24" {
		t.Fatal("gate retained caller slice")
	}
	gate.Clear(2)
	if _, err := gate.Acquire(); err != nil {
		t.Fatal("wrong generation cleared gate")
	}
	cancel()
	if _, err := gate.Acquire(); err == nil {
		t.Fatal("canceled generation remained usable")
	}
	gate.Clear(1)
	if _, err := gate.Acquire(); err == nil {
		t.Fatal("cleared gate remained usable")
	}
}
