//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seeker/uni-next/internal/config"
)

func TestRuntimeOptionsApplyCLIOverConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{
  "schema_version": 1,
  "server": {"host": "old.example", "port": 9443},
  "auth": {"username": "old-user", "mac": "02:00:00:00:00:01"},
  "tls": {"spki_sha256": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]},
  "network": {"allowed_routes": ["10.0.0.0/8"]}
}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	options := newRuntimeOptions("connect")
	cfg, _, err := options.parse([]string{
		"--config", path,
		"--server-host", "new.example",
		"--username", "new-user",
		"--route", "10.20.0.0/16",
		"--route", "10.30.0.0/16",
		"--http-listen", "127.0.0.1:8181",
	}, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Host != "new.example" || cfg.Auth.Username != "new-user" {
		t.Fatalf("scalar overrides were not applied: %#v", cfg)
	}
	if len(cfg.Network.AllowedRoutes) != 2 || cfg.Network.AllowedRoutes[0] != "10.20.0.0/16" || cfg.Network.AllowedRoutes[1] != "10.30.0.0/16" {
		t.Fatalf("route override did not replace config list: %v", cfg.Network.AllowedRoutes)
	}
	if !cfg.HTTP.Enabled || len(cfg.HTTP.Listeners) != 1 || cfg.HTTP.Listeners[0] != "127.0.0.1:8181" {
		t.Fatalf("HTTP listener override was not applied: %#v", cfg.HTTP)
	}
}

func TestRuntimeOptionsAllowCLIOnlyConfiguration(t *testing.T) {
	options := newRuntimeOptions("connect")
	cfg, _, err := options.parse([]string{
		"--server-host", "vpn.example",
		"--username", "user",
		"--mac", "02:00:00:00:00:01",
		"--spki-sha256", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"--route", "10.0.0.0/8",
	}, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Host != "vpn.example" || cfg.Server.Port != 9443 || len(cfg.Network.AllowedRoutes) != 1 {
		t.Fatalf("unexpected CLI-only configuration: %#v", cfg)
	}
}

func TestProxyHelpExitsSuccessfully(t *testing.T) {
	if code := run([]string{"proxy", "--help"}); code != 0 {
		t.Fatalf("proxy help exit code=%d, want 0", code)
	}
}
