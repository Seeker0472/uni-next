package proxy

import (
	"context"
	"net/netip"
	"testing"

	genstate "github.com/seeker/uni-next/internal/generation"
)

func TestResolveRequiresConfiguredAndActiveRoute(t *testing.T) {
	policy, err := NewPolicy([]string{"10.20.0.0/16"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	generation := genstate.Generation{Routes: []netip.Prefix{netip.MustParsePrefix("10.20.10.0/24")}}
	allowed, err := policy.Resolve(context.Background(), generation, "10.20.10.8", 443)
	if err != nil || allowed != netip.MustParseAddrPort("10.20.10.8:443") {
		t.Fatalf("allowed target resolved as %v, %v", allowed, err)
	}
	for _, denied := range []string{"10.20.11.8", "10.21.10.8", "127.0.0.1"} {
		if _, err := policy.Resolve(context.Background(), generation, denied, 443); err == nil {
			t.Fatalf("destination %s escaped policy intersection", denied)
		}
	}
}
