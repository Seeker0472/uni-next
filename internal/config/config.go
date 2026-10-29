// Package config loads and validates strict, versioned runtime configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const MaxConfigBytes = 1 << 20

type Config struct {
	SchemaVersion int       `json:"schema_version"`
	Protocol      Protocol  `json:"protocol"`
	Server        Server    `json:"server"`
	Auth          Auth      `json:"auth"`
	TLS           TLS       `json:"tls"`
	Network       Network   `json:"network"`
	Timeouts      Timeouts  `json:"timeouts"`
	Heartbeat     Heartbeat `json:"heartbeat"`
	Reconnect     Reconnect `json:"reconnect"`
	Socks         Socks     `json:"socks"`
	HTTP          HTTP      `json:"http"`
	Gateway       Gateway   `json:"gateway"`
	Runtime       Runtime   `json:"runtime"`
	Logging       Logging   `json:"logging"`
}

type Protocol struct {
	Profile string `json:"profile"`
}
type Server struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}
type Auth struct {
	Username         string `json:"username"`
	MAC              string `json:"mac"`
	PasswordFile     string `json:"password_file,omitempty"`
	LogoutUserIDFile string `json:"logout_user_id_file,omitempty"`
}
type TLS struct {
	SPKISHA256   []string `json:"spki_sha256,omitempty"`
	SPKIPinFile  string   `json:"spki_pin_file,omitempty"`
	CipherSuites []string `json:"cipher_suites"`
}
type Network struct {
	TunName       string   `json:"tun_name"`
	MTU           int      `json:"mtu"`
	AllowedRoutes []string `json:"allowed_routes"`
	Table         int      `json:"table"`
	RulePriority  int      `json:"rule_priority"`
}
type Timeouts struct {
	Connect     Duration `json:"connect"`
	TLS         Duration `json:"tls"`
	Auth        Duration `json:"auth"`
	ControlStep Duration `json:"control_step"`
	Write       Duration `json:"write"`
	Logout      Duration `json:"logout"`
}
type Heartbeat struct {
	Interval Duration `json:"interval"`
	Timeout  Duration `json:"timeout"`
}
type Reconnect struct {
	Network    NetworkReconnect `json:"network"`
	Initial    Duration         `json:"initial"`
	Maximum    Duration         `json:"maximum"`
	ResetAfter Duration         `json:"reset_after"`
	Kickout    Kickout          `json:"kickout"`
}
type NetworkReconnect struct {
	Enabled bool `json:"enabled"`
}
type Kickout struct {
	Mode       string   `json:"mode"`
	Window     Duration `json:"window"`
	MaxRetries int      `json:"max_retries"`
}
type Socks struct {
	Enabled             bool      `json:"enabled"`
	Listeners           []string  `json:"listeners"`
	Auth                SocksAuth `json:"auth"`
	AllowLoopbackNoAuth bool      `json:"allow_loopback_no_auth"`
	AllowSources        []string  `json:"allow_sources"`
	AllowedDestinations []string  `json:"allowed_destinations"`
	MaxTCPConnections   int       `json:"max_tcp_connections"`
	MaxPerSource        int       `json:"max_per_source"`
	HandshakeTimeout    Duration  `json:"handshake_timeout"`
	DialTimeout         Duration  `json:"dial_timeout"`
	TCPIdleTimeout      Duration  `json:"tcp_idle_timeout"`
	UDP                 SocksUDP  `json:"udp"`
}
type SocksAuth struct {
	Username     string `json:"username"`
	PasswordFile string `json:"password_file,omitempty"`
}
type SocksUDP struct {
	Enabled                  bool      `json:"enabled"`
	PortRange                PortRange `json:"port_range"`
	MaxAssociations          int       `json:"max_associations"`
	MaxRemotesPerAssociation int       `json:"max_remotes_per_association"`
	IdleTimeout              Duration  `json:"idle_timeout"`
}
type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}
type HTTP struct {
	Enabled             bool     `json:"enabled"`
	Listeners           []string `json:"listeners"`
	AllowedDestinations []string `json:"allowed_destinations"`
	MaxConnections      int      `json:"max_connections"`
	MaxPerSource        int      `json:"max_per_source"`
	ReadHeaderTimeout   Duration `json:"read_header_timeout"`
	DialTimeout         Duration `json:"dial_timeout"`
	IdleTimeout         Duration `json:"idle_timeout"`
}
type Gateway struct {
	Mode             string   `json:"mode"`
	IngressInterface string   `json:"ingress_interface,omitempty"`
	SourceCIDRs      []string `json:"source_cidrs,omitempty"`
	ExportRoutes     []string `json:"export_routes,omitempty"`
	ClampTCPMSS      bool     `json:"clamp_tcp_mss"`
}
type Runtime struct {
	StateDir string `json:"state_dir"`
	RunDir   string `json:"run_dir"`
}
type Logging struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

func Defaults() Config {
	return Config{
		SchemaVersion: 1,
		Protocol:      Protocol{Profile: "cnem-base-v1"},
		Server:        Server{Port: 9443},
		TLS:           TLS{CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}},
		Network:       Network{TunName: "uni-next0", MTU: 1300, Table: 20000, RulePriority: 100},
		Timeouts:      Timeouts{Connect: D(10 * time.Second), TLS: D(10 * time.Second), Auth: D(20 * time.Second), ControlStep: D(10 * time.Second), Write: D(10 * time.Second), Logout: D(5 * time.Second)},
		Heartbeat:     Heartbeat{Interval: D(10 * time.Second), Timeout: D(35 * time.Second)},
		Reconnect:     Reconnect{Network: NetworkReconnect{Enabled: true}, Initial: D(5 * time.Second), Maximum: D(60 * time.Second), ResetAfter: D(5 * time.Minute), Kickout: Kickout{Mode: "bounded", Window: D(10 * time.Minute), MaxRetries: 3}},
		Socks:         Socks{Listeners: []string{"127.0.0.1:1080"}, MaxTCPConnections: 512, MaxPerSource: 64, HandshakeTimeout: D(10 * time.Second), DialTimeout: D(10 * time.Second), UDP: SocksUDP{Enabled: true, PortRange: PortRange{From: 20000, To: 20255}, MaxAssociations: 128, MaxRemotesPerAssociation: 64, IdleTimeout: D(120 * time.Second)}},
		HTTP:          HTTP{Listeners: []string{"127.0.0.1:8080"}, MaxConnections: 512, MaxPerSource: 64, ReadHeaderTimeout: D(10 * time.Second), DialTimeout: D(10 * time.Second), IdleTimeout: D(2 * time.Minute)},
		Gateway:       Gateway{Mode: "off", ClampTCPMSS: true},
		Runtime:       Runtime{StateDir: "/var/lib/uni-next", RunDir: "/run/uni-next"},
		Logging:       Logging{Level: "info", Format: "text"},
	}
}

func Load(path string) (Config, error) {
	return Resolve(path, Defaults(), nil)
}

// Resolve decodes an optional strict JSON file over base, applies explicit
// overrides, and validates only the final configuration.
func Resolve(path string, base Config, apply func(*Config) error) (Config, error) {
	cfg := base
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return Config{}, fmt.Errorf("open config: %w", err)
		}
		defer file.Close()
		cfg, err = decodeOnto(file, base)
		if err != nil {
			return Config{}, err
		}
	}
	if apply != nil {
		if err := apply(&cfg); err != nil {
			return Config{}, err
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Decode(reader io.Reader) (Config, error) {
	cfg, err := decodeOnto(reader, Defaults())
	if err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func decodeOnto(reader io.Reader, base Config) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return Config{}, fmt.Errorf("config exceeds %d bytes", MaxConfigBytes)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return Config{}, err
	}
	cfg := base
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder, "$", 0); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	return ensureEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, path string, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s: object key is not a string", path)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%s.%s: duplicate key", path, key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, path+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("%s: malformed object", path)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index), depth+1); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("%s: malformed array", path)
		}
	default:
		return fmt.Errorf("%s: unexpected delimiter", path)
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	return errors.New("decode config: trailing JSON value")
}
