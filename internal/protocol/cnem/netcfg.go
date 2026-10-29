package cnem

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

const netConfigBodySize = 956

type Route struct {
	Prefix  netip.Prefix
	Gateway netip.Addr
}
type NetConfig struct {
	VIP       netip.Addr
	VIPPrefix netip.Prefix
	RouteType uint32
	Routes    []Route
	HasDNS    bool
}

func ParseNetConfig(body []byte) (NetConfig, error) {
	if len(body) != netConfigBodySize {
		return NetConfig{}, fmt.Errorf("netcfg body must contain %d bytes", netConfigBodySize)
	}
	vip, ok := netip.AddrFromSlice(body[0:4])
	if !ok || !vip.Is4() || vip.IsUnspecified() || vip.IsLoopback() || vip.IsMulticast() {
		return NetConfig{}, errors.New("netcfg VIP is invalid")
	}
	ones, bits := net.IPMask(body[4:8]).Size()
	if bits != 32 || ones < 1 {
		return NetConfig{}, errors.New("netcfg mask is not contiguous IPv4")
	}
	// Verified fixed layout: big-endian 2 at 0x08, zeros at 0x0c..0x13,
	// little-endian 1 at 0x1c, and zeros at 0xac..0xb7. The profile mixes
	// endianness and differs from the earlier table's 0x08/0x0c labels.
	if binary.BigEndian.Uint32(body[0x08:0x0c]) != 2 ||
		!allZero(body[0x0c:0x14]) ||
		binary.LittleEndian.Uint32(body[0x1c:0x20]) != 1 ||
		!allZero(body[0xac:0xb8]) {
		return NetConfig{}, errors.New("netcfg fixed fields do not match the supported profile")
	}
	routeType := binary.BigEndian.Uint32(body[0x14:0x18])
	if routeType != 1 {
		return NetConfig{}, fmt.Errorf("netcfg route type %d is unsupported", routeType)
	}
	routeBytes := binary.BigEndian.Uint32(body[0x18:0x1c])
	count := binary.BigEndian.Uint32(body[0xb8:0xbc])
	if count > (netConfigBodySize-0xbc)/12 || routeBytes != count*12 {
		return NetConfig{}, errors.New("netcfg route count and byte length are inconsistent")
	}
	routes := make([]Route, 0, count)
	for index := range count {
		offset := 0xbc + int(index)*12
		destination, ok := netip.AddrFromSlice(body[offset : offset+4])
		if !ok || !destination.Is4() {
			return NetConfig{}, errors.New("netcfg route destination is invalid")
		}
		routeOnes, routeBits := net.IPMask(body[offset+4 : offset+8]).Size()
		if routeBits != 32 || routeOnes == 0 {
			return NetConfig{}, errors.New("netcfg route mask is invalid or default route is unsupported")
		}
		gateway, ok := netip.AddrFromSlice(body[offset+8 : offset+12])
		if !ok || !gateway.Is4() || !gateway.IsUnspecified() {
			return NetConfig{}, errors.New("netcfg route gateway is unsupported")
		}
		prefix := netip.PrefixFrom(destination, routeOnes).Masked()
		if prefix.Addr().IsUnspecified() || prefix.Addr().IsLoopback() || prefix.Addr().IsMulticast() {
			return NetConfig{}, fmt.Errorf("netcfg route %s is unsafe", prefix)
		}
		routes = append(routes, Route{Prefix: prefix, Gateway: gateway})
	}
	if !allZero(body[0xbc+int(count)*12:]) {
		return NetConfig{}, errors.New("netcfg trailing route area is not zero-filled")
	}
	hasDNS := false
	for _, value := range body[0xa0:0xac] {
		hasDNS = hasDNS || value != 0
	}
	return NetConfig{VIP: vip, VIPPrefix: netip.PrefixFrom(vip, ones), RouteType: routeType, Routes: routes, HasDNS: hasDNS}, nil
}
