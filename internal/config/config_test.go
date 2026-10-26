package config

import (
	"os"
	"strings"
	"testing"
)

func TestExampleConfigurationLoads(t *testing.T) {
	file, err := os.Open("../../docs/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cfg, err := Decode(file)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol.Profile != "huawei-linux-base-v1" || cfg.Network.MTU != 1300 || !cfg.Socks.UDP.Enabled {
		t.Fatalf("unexpected decoded configuration: %#v", cfg)
	}
}

func TestDecodeRejectsDuplicateAndUnknownKeys(t *testing.T) {
	base := `{"schema_version":1,"protocol":{"profile":"huawei-linux-base-v1"},"server":{"host":"192.0.2.1","port":9443},"auth":{"username":"u","mac":"02:00:00:00:00:01"},"tls":{"spki_sha256":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],"cipher_suites":["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]},"network":{"allowed_routes":["10.0.0.0/24"]}}`
	for name, input := range map[string]string{
		"duplicate": strings.Replace(base, `"port":9443`, `"port":9443,"port":9444`, 1),
		"unknown":   strings.Replace(base, `"server":{`, `"unexpected":true,"server":{`, 1),
		"trailing":  base + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatal("expected strict decode failure")
			}
		})
	}
}

func TestValidationRejectsUnsafeRemoteProxy(t *testing.T) {
	for name, listener := range map[string]string{
		"unspecified listener": "0.0.0.0:1080",
		"unbounded source":     "192.0.2.2:1080",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Server.Host = "192.0.2.1"
			cfg.Auth.Username = "u"
			cfg.Auth.MAC = "02:00:00:00:00:01"
			cfg.TLS.SPKISHA256 = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
			cfg.Network.AllowedRoutes = []string{"10.0.0.0/24"}
			cfg.Socks.Enabled = true
			cfg.Socks.Listeners = []string{listener}
			cfg.Socks.AllowSources = []string{"0.0.0.0/0"}
			cfg.Socks.Auth.Username = "proxy"
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected unsafe remote proxy to be rejected")
			}
		})
	}
}

func TestValidationRejectsUnboundedGatewaySources(t *testing.T) {
	cfg := Defaults()
	cfg.Server.Host = "192.0.2.1"
	cfg.Auth.Username = "u"
	cfg.Auth.MAC = "02:00:00:00:00:01"
	cfg.TLS.SPKISHA256 = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	cfg.Network.AllowedRoutes = []string{"10.0.0.0/24"}
	cfg.Gateway.Mode = "netbird"
	cfg.Gateway.IngressInterface = "wt0"
	cfg.Gateway.SourceCIDRs = []string{"0.0.0.0/0"}
	cfg.Gateway.ExportRoutes = []string{"10.0.0.0/24"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected unbounded gateway source to be rejected")
	}
}
