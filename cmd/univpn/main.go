//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/seeker/univpn/internal/apperr"
	"github.com/seeker/univpn/internal/config"
	"github.com/seeker/univpn/internal/credential"
	"github.com/seeker/univpn/internal/session"
	"github.com/seeker/univpn/internal/status"
	"github.com/seeker/univpn/internal/transport"
)

var version = "development"

func main() { apperr.SetCanceledSentinel(context.Canceled); os.Exit(run(os.Args[1:])) }

func run(arguments []string) int {
	if len(arguments) == 0 {
		usage()
		return 20
	}
	var err error
	switch arguments[0] {
	case "connect":
		err = connect(arguments[1:])
	case "check-config":
		err = checkConfig(arguments[1:])
	case "status":
		err = showStatus(arguments[1:])
	case "version":
		fmt.Printf("univpn %s\n", version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", arguments[0])
		usage()
		return 20
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "univpn:", err)
	}
	return apperr.ExitCode(err)
}

func connect(arguments []string) error {
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "path to strict JSON configuration")
	vpnPassword := flags.String("vpn-password-file", "", "runtime VPN password file")
	logoutUserID := flags.String("logout-user-id-file", "", "runtime logout user ID file")
	socksPassword := flags.String("socks-password-file", "", "runtime SOCKS password file")
	if err := flags.Parse(arguments); err != nil {
		return apperr.Wrap(apperr.CodeConfig, "cli", apperr.RetryNever, "invalid arguments", err)
	}
	if *configPath == "" || flags.NArg() != 0 {
		return apperr.New(apperr.CodeConfig, "cli", apperr.RetryNever, "connect requires --config and no positional arguments")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return apperr.Wrap(apperr.CodeConfig, "configuration", apperr.RetryNever, err.Error(), err)
	}
	logger, err := newLogger(cfg)
	if err != nil {
		return err
	}
	values, err := credential.Load(cfg, credential.Overrides{VPNPasswordFile: *vpnPassword, LogoutUserIDFile: *logoutUserID, SocksPasswordFile: *socksPassword}, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	defer values.Clear()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return (session.Runtime{Config: cfg, Credentials: values, Logger: logger}).Run(ctx)
}

func checkConfig(arguments []string) error {
	flags := flag.NewFlagSet("check-config", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "path to strict JSON configuration")
	if err := flags.Parse(arguments); err != nil {
		return apperr.Wrap(apperr.CodeConfig, "cli", apperr.RetryNever, "invalid arguments", err)
	}
	if *configPath == "" || flags.NArg() != 0 {
		return apperr.New(apperr.CodeConfig, "cli", apperr.RetryNever, "check-config requires --config and no positional arguments")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return apperr.Wrap(apperr.CodeConfig, "configuration", apperr.RetryNever, err.Error(), err)
	}
	if _, err := transport.NewDialer(cfg); err != nil {
		return err
	}
	fmt.Println("configuration is valid")
	return nil
}

func showStatus(arguments []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	runDir := flags.String("run-dir", "/run/univpn", "runtime status directory")
	jsonOutput := flags.Bool("json", false, "print JSON")
	if err := flags.Parse(arguments); err != nil {
		return apperr.Wrap(apperr.CodeConfig, "cli", apperr.RetryNever, "invalid arguments", err)
	}
	if flags.NArg() != 0 {
		return apperr.New(apperr.CodeConfig, "cli", apperr.RetryNever, "status accepts no positional arguments")
	}
	snapshot, err := status.Read(*runDir)
	if err != nil {
		return apperr.Wrap(apperr.CodeConfig, "status", apperr.RetryNever, "cannot read live status", err)
	}
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(snapshot)
	}
	fmt.Printf("phase: %s\ngeneration: %d\nVIP: %s\nroutes: %s\nSOCKS ready: %t\nreconnects: %d\n", snapshot.Phase, snapshot.Generation, snapshot.VIP, strings.Join(snapshot.Routes, ", "), snapshot.SocksReady, snapshot.Reconnects)
	if snapshot.LastError != "" {
		fmt.Printf("last error: %s\n", snapshot.LastError)
	}
	return nil
}

func newLogger(cfg config.Config) (*slog.Logger, error) {
	levels := map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError}
	level, ok := levels[cfg.Logging.Level]
	if !ok {
		return nil, errors.New("invalid logging level")
	}
	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if cfg.Logging.Format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, options)
	} else {
		handler = slog.NewTextHandler(os.Stderr, options)
	}
	return slog.New(handler), nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: univpn <connect|check-config|status|version> [options]")
}
