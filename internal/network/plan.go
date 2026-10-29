// Package network computes validated kernel network plans without mutating the host.
package network

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/seeker/uni-next/internal/config"
	protocol "github.com/seeker/uni-next/internal/protocol/univpn"
)

type Plan struct {
	VIP       netip.Addr
	VIPPrefix netip.Prefix
	Routes    []netip.Prefix
	Protected []netip.Prefix
}

func BuildPlan(cfg config.Config, negotiated protocol.NetConfig) (Plan, error) {
	allowed, err := parsePrefixes(cfg.Network.AllowedRoutes)
	if err != nil {
		return Plan{}, err
	}
	protected := slices.Clone(allowed)
	effectiveSet := make(map[netip.Prefix]struct{})
	for _, serverRoute := range negotiated.Routes {
		for _, allowedRoute := range allowed {
			if intersection, ok := intersect(serverRoute.Prefix, allowedRoute); ok {
				effectiveSet[intersection] = struct{}{}
			}
		}
	}
	routes := make([]netip.Prefix, 0, len(effectiveSet))
	for route := range effectiveSet {
		routes = append(routes, route)
	}
	sortPrefixes(routes)
	sortPrefixes(protected)
	if len(routes) == 0 {
		return Plan{}, fmt.Errorf("server supplied no route allowed by network.allowed_routes")
	}
	if cfg.Gateway.Mode == "netbird" {
		exports, err := parsePrefixes(cfg.Gateway.ExportRoutes)
		if err != nil {
			return Plan{}, err
		}
		for _, exported := range exports {
			if !coveredByAny(exported, routes) {
				return Plan{}, fmt.Errorf("exported route %s is not present in negotiated routes", exported)
			}
		}
	}
	return Plan{VIP: negotiated.VIP, VIPPrefix: negotiated.VIPPrefix, Routes: routes, Protected: protected}, nil
}

func ProtectionPlan(cfg config.Config) ([]netip.Prefix, error) {
	prefixes, err := parsePrefixes(cfg.Network.AllowedRoutes)
	if err != nil {
		return nil, err
	}
	sortPrefixes(prefixes)
	return prefixes, nil
}

func intersect(left, right netip.Prefix) (netip.Prefix, bool) {
	left = left.Masked()
	right = right.Masked()
	if left.Bits() <= right.Bits() && left.Contains(right.Addr()) {
		return right, true
	}
	if right.Bits() <= left.Bits() && right.Contains(left.Addr()) {
		return left, true
	}
	return netip.Prefix{}, false
}

func coveredByAny(candidate netip.Prefix, routes []netip.Prefix) bool {
	for _, route := range routes {
		if route.Bits() <= candidate.Bits() && route.Contains(candidate.Addr()) {
			return true
		}
	}
	return false
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func sortPrefixes(prefixes []netip.Prefix) {
	slices.SortFunc(prefixes, func(left, right netip.Prefix) int {
		if compare := left.Addr().Compare(right.Addr()); compare != 0 {
			return compare
		}
		return left.Bits() - right.Bits()
	})
}
