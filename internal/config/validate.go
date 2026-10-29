package config

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

var allowedCipherSuites = map[string]uint16{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

func CipherSuiteIDs(names []string) ([]uint16, error) {
	ids := make([]uint16, 0, len(names))
	seen := make(map[uint16]struct{})
	for _, name := range names {
		id, ok := allowedCipherSuites[name]
		if !ok {
			return nil, fmt.Errorf("tls.cipher_suites: unsupported suite %q", name)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("tls.cipher_suites: duplicate suite %q", name)
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("tls.cipher_suites must not be empty")
	}
	return ids, nil
}

func (c Config) Validate() error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("schema_version: unsupported version %d", c.SchemaVersion)
	}
	if c.Protocol.Profile != "huawei-linux-base-v1" {
		return fmt.Errorf("protocol.profile: unsupported profile %q", c.Protocol.Profile)
	}
	if strings.TrimSpace(c.Server.Host) == "" {
		return fmt.Errorf("server.host: must not be empty")
	}
	if strings.ContainsAny(c.Server.Host, "\r\n") {
		return fmt.Errorf("server.host: contains invalid control characters")
	}
	if c.Server.Port == 0 {
		return fmt.Errorf("server.port: must be non-zero")
	}
	if strings.TrimSpace(c.Auth.Username) == "" || strings.ContainsAny(c.Auth.Username, "\r\n") {
		return fmt.Errorf("auth.username: must be non-empty and contain no CR/LF")
	}
	mac, err := net.ParseMAC(c.Auth.MAC)
	if err != nil || len(mac) != 6 {
		return fmt.Errorf("auth.mac: must be a six-byte MAC address")
	}
	if (len(c.TLS.SPKISHA256) == 0) == (c.TLS.SPKIPinFile == "") {
		return fmt.Errorf("tls: configure exactly one of spki_sha256 or spki_pin_file")
	}
	for i, pin := range c.TLS.SPKISHA256 {
		if _, err := ParsePin(pin); err != nil {
			return fmt.Errorf("tls.spki_sha256[%d]: %w", i, err)
		}
	}
	if _, err := CipherSuiteIDs(c.TLS.CipherSuites); err != nil {
		return err
	}
	if err := validateName("network.tun_name", c.Network.TunName, 15); err != nil {
		return err
	}
	if c.Network.MTU < 576 || c.Network.MTU > 1300 {
		return fmt.Errorf("network.mtu: must be between 576 and 1300")
	}
	allowed, err := parsePrefixes("network.allowed_routes", c.Network.AllowedRoutes, true)
	if err != nil {
		return err
	}
	if len(allowed) == 0 {
		return fmt.Errorf("network.allowed_routes: must not be empty")
	}
	if c.Network.Table <= 0 || c.Network.Table > 0x7fffffff {
		return fmt.Errorf("network.table: out of range")
	}
	if c.Network.RulePriority <= 0 || c.Network.RulePriority >= 32766 {
		return fmt.Errorf("network.rule_priority: must be between 1 and 32765")
	}
	if err := c.validateDurations(); err != nil {
		return err
	}
	if !slices.Contains([]string{"stop", "bounded", "always"}, c.Reconnect.Kickout.Mode) {
		return fmt.Errorf("reconnect.kickout.mode: expected stop, bounded, or always")
	}
	if c.Reconnect.Kickout.MaxRetries < 0 {
		return fmt.Errorf("reconnect.kickout.max_retries: must not be negative")
	}
	if c.Reconnect.Kickout.Mode == "bounded" && c.Reconnect.Kickout.MaxRetries == 0 {
		return fmt.Errorf("reconnect.kickout.max_retries: bounded mode requires a positive value")
	}
	if err := c.validateSocks(allowed); err != nil {
		return err
	}
	if err := c.validateHTTP(allowed); err != nil {
		return err
	}
	if err := c.validateGateway(allowed); err != nil {
		return err
	}
	if !filepath.IsAbs(c.Runtime.StateDir) || !filepath.IsAbs(c.Runtime.RunDir) {
		return fmt.Errorf("runtime state_dir and run_dir must be absolute")
	}
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, c.Logging.Level) {
		return fmt.Errorf("logging.level: unsupported value %q", c.Logging.Level)
	}
	if !slices.Contains([]string{"text", "json"}, c.Logging.Format) {
		return fmt.Errorf("logging.format: unsupported value %q", c.Logging.Format)
	}
	return nil
}

func (c Config) validateDurations() error {
	positive := map[string]time.Duration{
		"timeouts.connect": c.Timeouts.Connect.Duration, "timeouts.tls": c.Timeouts.TLS.Duration,
		"timeouts.auth": c.Timeouts.Auth.Duration, "timeouts.control_step": c.Timeouts.ControlStep.Duration,
		"timeouts.write": c.Timeouts.Write.Duration, "timeouts.logout": c.Timeouts.Logout.Duration,
		"heartbeat.interval": c.Heartbeat.Interval.Duration, "heartbeat.timeout": c.Heartbeat.Timeout.Duration,
		"reconnect.initial": c.Reconnect.Initial.Duration, "reconnect.maximum": c.Reconnect.Maximum.Duration,
		"reconnect.reset_after": c.Reconnect.ResetAfter.Duration, "reconnect.kickout.window": c.Reconnect.Kickout.Window.Duration,
	}
	for name, value := range positive {
		if value <= 0 {
			return fmt.Errorf("%s: must be positive", name)
		}
	}
	if c.Heartbeat.Timeout.Duration <= c.Heartbeat.Interval.Duration {
		return fmt.Errorf("heartbeat.timeout: must be greater than heartbeat.interval")
	}
	if c.Reconnect.Maximum.Duration < c.Reconnect.Initial.Duration {
		return fmt.Errorf("reconnect.maximum: must be at least reconnect.initial")
	}
	return nil
}

func (c Config) validateSocks(allowed []netip.Prefix) error {
	if !c.Socks.Enabled {
		return nil
	}
	if len(c.Socks.Listeners) == 0 {
		return fmt.Errorf("socks.listeners: must not be empty when enabled")
	}
	remote := false
	seen := make(map[netip.AddrPort]struct{})
	for i, raw := range c.Socks.Listeners {
		address, err := netip.ParseAddrPort(raw)
		if err != nil || !address.Addr().Is4() || address.Addr().IsUnspecified() {
			return fmt.Errorf("socks.listeners[%d]: must be an explicit IPv4 address and port", i)
		}
		if _, duplicate := seen[address]; duplicate {
			return fmt.Errorf("socks.listeners[%d]: duplicate listener", i)
		}
		seen[address] = struct{}{}
		remote = remote || !address.Addr().IsLoopback()
	}
	sources, err := parsePrefixes("socks.allow_sources", c.Socks.AllowSources, false)
	if err != nil {
		return err
	}
	if err := validateSourcePrefixes("socks.allow_sources", sources); err != nil {
		return err
	}
	if remote && len(sources) == 0 {
		return fmt.Errorf("socks.allow_sources: required for non-loopback listeners")
	}
	if remote && strings.TrimSpace(c.Socks.Auth.Username) == "" {
		return fmt.Errorf("socks.auth.username: required for non-loopback listeners")
	}
	if strings.ContainsAny(c.Socks.Auth.Username, "\x00\r\n") || len(c.Socks.Auth.Username) > 255 {
		return fmt.Errorf("socks.auth.username: invalid RFC 1929 username")
	}
	destinations, err := parsePrefixes("socks.allowed_destinations", c.Socks.AllowedDestinations, true)
	if err != nil {
		return err
	}
	if len(destinations) == 0 {
		destinations = allowed
	}
	for _, destination := range destinations {
		if !coveredBy(destination, allowed) {
			return fmt.Errorf("socks.allowed_destinations: %s exceeds network.allowed_routes", destination)
		}
	}
	if c.Socks.MaxTCPConnections <= 0 || c.Socks.MaxPerSource <= 0 || c.Socks.MaxPerSource > c.Socks.MaxTCPConnections {
		return fmt.Errorf("socks connection limits are invalid")
	}
	if c.Socks.HandshakeTimeout.Duration <= 0 || c.Socks.DialTimeout.Duration <= 0 || c.Socks.TCPIdleTimeout.Duration < 0 {
		return fmt.Errorf("socks timeouts are invalid")
	}
	if c.Socks.UDP.Enabled {
		ports := int(c.Socks.UDP.PortRange.To) - int(c.Socks.UDP.PortRange.From) + 1
		if c.Socks.UDP.PortRange.From == 0 || ports <= 0 {
			return fmt.Errorf("socks.udp.port_range: invalid range")
		}
		if c.Socks.UDP.MaxAssociations <= 0 || c.Socks.UDP.MaxAssociations > ports {
			return fmt.Errorf("socks.udp.max_associations: must fit in port_range")
		}
		if c.Socks.UDP.MaxRemotesPerAssociation <= 0 || c.Socks.UDP.IdleTimeout.Duration <= 0 {
			return fmt.Errorf("socks.udp limits must be positive")
		}
	}
	return nil
}

func (c Config) validateHTTP(allowed []netip.Prefix) error {
	if !c.HTTP.Enabled {
		return nil
	}
	if len(c.HTTP.Listeners) == 0 {
		return fmt.Errorf("http.listeners: must not be empty when enabled")
	}
	seen := make(map[netip.AddrPort]struct{})
	for i, raw := range c.HTTP.Listeners {
		address, err := netip.ParseAddrPort(raw)
		if err != nil || !address.Addr().Is4() || !address.Addr().IsLoopback() {
			return fmt.Errorf("http.listeners[%d]: must be an explicit IPv4 loopback address and port", i)
		}
		if _, duplicate := seen[address]; duplicate {
			return fmt.Errorf("http.listeners[%d]: duplicate listener", i)
		}
		seen[address] = struct{}{}
	}
	destinations, err := parsePrefixes("http.allowed_destinations", c.HTTP.AllowedDestinations, true)
	if err != nil {
		return err
	}
	if len(destinations) == 0 {
		destinations = allowed
	}
	for _, destination := range destinations {
		if !coveredBy(destination, allowed) {
			return fmt.Errorf("http.allowed_destinations: %s exceeds network.allowed_routes", destination)
		}
	}
	if c.HTTP.MaxConnections <= 0 || c.HTTP.MaxPerSource <= 0 || c.HTTP.MaxPerSource > c.HTTP.MaxConnections {
		return fmt.Errorf("http connection limits are invalid")
	}
	if c.HTTP.ReadHeaderTimeout.Duration <= 0 || c.HTTP.DialTimeout.Duration <= 0 || c.HTTP.IdleTimeout.Duration < 0 {
		return fmt.Errorf("http timeouts are invalid")
	}
	return nil
}

// ValidateProxyMode enforces the no-host-network-mutation boundary of proxy.
func (c Config) ValidateProxyMode() error {
	if c.Gateway.Mode != "off" {
		return fmt.Errorf("gateway.mode: proxy mode requires off")
	}
	if !c.Socks.Enabled && !c.HTTP.Enabled {
		return fmt.Errorf("proxy mode requires socks.enabled or http.enabled")
	}
	for i, raw := range c.Socks.Listeners {
		address, err := netip.ParseAddrPort(raw)
		if c.Socks.Enabled && (err != nil || !address.Addr().IsLoopback()) {
			return fmt.Errorf("socks.listeners[%d]: proxy mode permits loopback listeners only", i)
		}
	}
	return nil
}

func (c Config) validateGateway(allowed []netip.Prefix) error {
	if c.Gateway.Mode != "off" && c.Gateway.Mode != "netbird" {
		return fmt.Errorf("gateway.mode: expected off or netbird")
	}
	if c.Gateway.Mode == "off" {
		return nil
	}
	if err := validateName("gateway.ingress_interface", c.Gateway.IngressInterface, 15); err != nil {
		return err
	}
	sources, err := parsePrefixes("gateway.source_cidrs", c.Gateway.SourceCIDRs, false)
	if err != nil {
		return err
	}
	if err := validateSourcePrefixes("gateway.source_cidrs", sources); err != nil {
		return err
	}
	if len(sources) == 0 {
		return fmt.Errorf("gateway.source_cidrs: required in netbird mode")
	}
	exports, err := parsePrefixes("gateway.export_routes", c.Gateway.ExportRoutes, true)
	if err != nil {
		return err
	}
	if len(exports) == 0 {
		return fmt.Errorf("gateway.export_routes: required in netbird mode")
	}
	for _, route := range exports {
		if !coveredBy(route, allowed) {
			return fmt.Errorf("gateway.export_routes: %s exceeds network.allowed_routes", route)
		}
	}
	return nil
}

func validateSourcePrefixes(name string, prefixes []netip.Prefix) error {
	for index, prefix := range prefixes {
		if prefix.Bits() == 0 || prefix.Addr().IsMulticast() {
			return fmt.Errorf("%s[%d]: source range %s is too broad or invalid", name, index, prefix)
		}
	}
	return nil
}

func ParsePin(raw string) ([32]byte, error) {
	var result [32]byte
	value := strings.TrimSpace(strings.TrimPrefix(raw, "sha256/"))
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = hex.DecodeString(value)
	}
	if err != nil || len(decoded) != len(result) {
		return result, fmt.Errorf("pin must be SHA-256 in base64 or hex")
	}
	copy(result[:], decoded)
	return result, nil
}

func parsePrefixes(name string, values []string, forbidSpecial bool) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]struct{})
	for i, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("%s[%d]: expected IPv4 CIDR", name, i)
		}
		prefix = prefix.Masked()
		if forbidSpecial && (prefix.Bits() == 0 || prefix.Addr().IsLoopback() || prefix.Addr().IsMulticast() || prefix.Addr().IsUnspecified()) {
			return nil, fmt.Errorf("%s[%d]: unsafe route %s", name, i, prefix)
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, fmt.Errorf("%s[%d]: duplicate %s", name, i, prefix)
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func coveredBy(candidate netip.Prefix, allowed []netip.Prefix) bool {
	for _, parent := range allowed {
		if parent.Bits() <= candidate.Bits() && parent.Contains(candidate.Addr()) {
			return true
		}
	}
	return false
}

func validateName(name, value string, max int) error {
	if value == "" || len(value) > max {
		return fmt.Errorf("%s: must contain 1..%d bytes", name, max)
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return fmt.Errorf("%s: contains invalid character %q", name, r)
		}
	}
	return nil
}
