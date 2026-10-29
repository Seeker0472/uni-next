//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/seeker/uni-next/internal/config"
	"github.com/seeker/uni-next/internal/credential"
)

type stringListFlag struct {
	values []string
}

func (f *stringListFlag) String() string { return fmt.Sprint(f.values) }
func (f *stringListFlag) Set(value string) error {
	if value == "" {
		return errors.New("value must not be empty")
	}
	f.values = append(f.values, value)
	return nil
}

type runtimeOptions struct {
	flags *flag.FlagSet

	configPath     *string
	vpnPassword    *string
	logoutUserID   *string
	socksPassword  *string
	serverHost     *string
	serverPort     *uint
	username       *string
	mac            *string
	spkiPinFile    *string
	socksEnabled   *bool
	socksNoAuth    *bool
	httpEnabled    *bool
	runDir         *string
	stateDir       *string
	logLevel       *string
	logFormat      *string
	spkiPins       stringListFlag
	routes         stringListFlag
	socksListeners stringListFlag
	httpListeners  stringListFlag
}

func newRuntimeOptions(command string) *runtimeOptions {
	set := flag.NewFlagSet(command, flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	options := &runtimeOptions{flags: set}
	options.configPath = set.String("config", "", "optional path to strict JSON configuration")
	options.vpnPassword = set.String("vpn-password-file", "", "runtime VPN password file")
	options.logoutUserID = set.String("logout-user-id-file", "", "runtime logout user ID file")
	options.socksPassword = set.String("socks-password-file", "", "runtime SOCKS password file")
	options.serverHost = set.String("server-host", "", "override server.host")
	options.serverPort = set.Uint("server-port", 0, "override server.port")
	options.username = set.String("username", "", "override auth.username")
	options.mac = set.String("mac", "", "override auth.mac")
	options.spkiPinFile = set.String("spki-pin-file", "", "override tls.spki_pin_file")
	options.socksEnabled = set.Bool("socks", false, "override socks.enabled")
	options.socksNoAuth = set.Bool("socks-loopback-no-auth", false, "override socks.allow_loopback_no_auth")
	options.httpEnabled = set.Bool("http", false, "override http.enabled")
	options.runDir = set.String("run-dir", "", "override runtime.run_dir")
	options.stateDir = set.String("state-dir", "", "override runtime.state_dir")
	options.logLevel = set.String("log-level", "", "override logging.level")
	options.logFormat = set.String("log-format", "", "override logging.format")
	set.Var(&options.spkiPins, "spki-sha256", "replace tls.spki_sha256; repeat for multiple pins")
	set.Var(&options.routes, "route", "replace network.allowed_routes; repeat for multiple routes")
	set.Var(&options.socksListeners, "socks-listen", "replace socks.listeners; repeat for multiple listeners")
	set.Var(&options.httpListeners, "http-listen", "replace http.listeners; repeat for multiple listeners")
	return options
}

func (o *runtimeOptions) parse(arguments []string, base config.Config) (config.Config, credential.Overrides, error) {
	if err := o.flags.Parse(arguments); err != nil {
		return config.Config{}, credential.Overrides{}, err
	}
	if o.flags.NArg() != 0 {
		return config.Config{}, credential.Overrides{}, errors.New("positional arguments are not accepted")
	}
	set := make(map[string]bool)
	o.flags.Visit(func(value *flag.Flag) { set[value.Name] = true })
	cfg, err := config.Resolve(*o.configPath, base, func(cfg *config.Config) error {
		if set["server-host"] {
			cfg.Server.Host = *o.serverHost
		}
		if set["server-port"] {
			if *o.serverPort == 0 || *o.serverPort > 65535 {
				return errors.New("server-port must be between 1 and 65535")
			}
			cfg.Server.Port = uint16(*o.serverPort)
		}
		if set["username"] {
			cfg.Auth.Username = *o.username
		}
		if set["mac"] {
			cfg.Auth.MAC = *o.mac
		}
		if set["spki-sha256"] && set["spki-pin-file"] {
			return errors.New("spki-sha256 and spki-pin-file are mutually exclusive")
		}
		if set["spki-sha256"] {
			cfg.TLS.SPKISHA256 = append([]string(nil), o.spkiPins.values...)
			cfg.TLS.SPKIPinFile = ""
		}
		if set["spki-pin-file"] {
			cfg.TLS.SPKIPinFile = *o.spkiPinFile
			cfg.TLS.SPKISHA256 = nil
		}
		if set["route"] {
			cfg.Network.AllowedRoutes = append([]string(nil), o.routes.values...)
		}
		if set["socks-listen"] {
			if set["socks"] && !*o.socksEnabled {
				return errors.New("socks-listen conflicts with socks=false")
			}
			cfg.Socks.Listeners = append([]string(nil), o.socksListeners.values...)
			cfg.Socks.Enabled = true
		}
		if set["socks"] {
			cfg.Socks.Enabled = *o.socksEnabled
		}
		if set["socks-loopback-no-auth"] {
			cfg.Socks.AllowLoopbackNoAuth = *o.socksNoAuth
		}
		if set["http-listen"] {
			if set["http"] && !*o.httpEnabled {
				return errors.New("http-listen conflicts with http=false")
			}
			cfg.HTTP.Listeners = append([]string(nil), o.httpListeners.values...)
			cfg.HTTP.Enabled = true
		}
		if set["http"] {
			cfg.HTTP.Enabled = *o.httpEnabled
		}
		if set["run-dir"] {
			cfg.Runtime.RunDir = *o.runDir
		}
		if set["state-dir"] {
			cfg.Runtime.StateDir = *o.stateDir
		}
		if set["log-level"] {
			cfg.Logging.Level = *o.logLevel
		}
		if set["log-format"] {
			cfg.Logging.Format = *o.logFormat
		}
		return nil
	})
	if err != nil {
		return config.Config{}, credential.Overrides{}, err
	}
	credentials := credential.Overrides{
		VPNPasswordFile:   *o.vpnPassword,
		LogoutUserIDFile:  *o.logoutUserID,
		SocksPasswordFile: *o.socksPassword,
	}
	return cfg, credentials, nil
}

func proxyDefaults() (config.Config, error) {
	cfg := config.Defaults()
	cfg.Socks.Enabled = true
	cfg.Socks.AllowLoopbackNoAuth = true
	cfg.HTTP.Enabled = true

	runBase := os.Getenv("XDG_RUNTIME_DIR")
	if runBase == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return config.Config{}, fmt.Errorf("resolve user runtime directory: %w", err)
		}
		runBase = cache
	}
	stateBase, err := os.UserConfigDir()
	if err != nil {
		return config.Config{}, fmt.Errorf("resolve user state directory: %w", err)
	}
	cfg.Runtime.RunDir = filepath.Join(runBase, "uni-next")
	cfg.Runtime.StateDir = filepath.Join(stateBase, "uni-next")
	return cfg, nil
}
