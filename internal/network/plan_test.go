package network

import (
	"net/netip"
	"testing"

	"github.com/seeker/univpn/internal/config"
	protocol "github.com/seeker/univpn/internal/protocol/univpn"
)

func TestBuildPlanIntersectsServerAndOperatorRoutes(t *testing.T) {
	cfg := config.Defaults()
	cfg.Network.AllowedRoutes = []string{"10.19.20.0/25", "10.20.0.0/16"}
	cfg.Gateway.Mode = "netbird"
	cfg.Gateway.ExportRoutes = []string{"10.19.20.0/25"}
	netConfig := protocol.NetConfig{VIP: netip.MustParseAddr("10.255.250.1"), VIPPrefix: netip.MustParsePrefix("10.255.250.1/24"), Routes: []protocol.Route{{Prefix: netip.MustParsePrefix("10.19.20.0/24")}, {Prefix: netip.MustParsePrefix("10.20.10.0/24")}, {Prefix: netip.MustParsePrefix("10.30.0.0/16")}}}
	plan, err := BuildPlan(cfg, netConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 2 || plan.Routes[0].String() != "10.19.20.0/25" || plan.Routes[1].String() != "10.20.10.0/24" {
		t.Fatalf("unexpected routes: %v", plan.Routes)
	}
}

func TestBuildPlanRequiresEveryExport(t *testing.T) {
	cfg := config.Defaults()
	cfg.Network.AllowedRoutes = []string{"10.0.0.0/8"}
	cfg.Gateway.Mode = "netbird"
	cfg.Gateway.ExportRoutes = []string{"10.2.0.0/16"}
	netConfig := protocol.NetConfig{VIP: netip.MustParseAddr("10.255.1.1"), VIPPrefix: netip.MustParsePrefix("10.255.1.1/24"), Routes: []protocol.Route{{Prefix: netip.MustParsePrefix("10.1.0.0/16")}}}
	if _, err := BuildPlan(cfg, netConfig); err == nil {
		t.Fatal("expected missing export rejection")
	}
}
