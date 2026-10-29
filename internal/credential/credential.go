// Package credential resolves bounded runtime secrets without logging them.
package credential

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/seeker/uni-next/internal/apperr"
	"github.com/seeker/uni-next/internal/config"
	"golang.org/x/term"
)

const maxSecretBytes = 64 << 10

type Values struct {
	VPNPassword   []byte
	LogoutUserID  []byte
	SocksPassword []byte
}

type Overrides struct {
	VPNPasswordFile   string
	LogoutUserIDFile  string
	SocksPasswordFile string
}

func Load(cfg config.Config, overrides Overrides, stdin *os.File, stderr io.Writer) (Values, error) {
	vpnPath, vpnExplicit := choose(overrides.VPNPasswordFile, cfg.Auth.PasswordFile, credentialPath("vpn-password"))
	logoutPath, _ := choose(overrides.LogoutUserIDFile, cfg.Auth.LogoutUserIDFile, credentialPath("logout-user-id"))
	socksPath, _ := choose(overrides.SocksPasswordFile, cfg.Socks.Auth.PasswordFile, credentialPath("socks-password"))
	var result Values
	var err error
	loaded := false
	defer func() {
		if !loaded {
			result.Clear()
		}
	}()
	if vpnPath != "" {
		result.VPNPassword, err = readSecret(vpnPath)
		if err != nil {
			return Values{}, secretError("vpn password", err)
		}
	} else if !vpnExplicit && stdin != nil && term.IsTerminal(int(stdin.Fd())) {
		if _, err := fmt.Fprint(stderr, "VPN password: "); err != nil {
			return Values{}, secretError("vpn password", err)
		}
		result.VPNPassword, err = term.ReadPassword(int(stdin.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return Values{}, secretError("vpn password", err)
		}
	} else {
		return Values{}, apperr.New(apperr.CodeConfig, "credentials", apperr.RetryNever, "VPN password is required")
	}
	if logoutPath == "" {
		return Values{}, apperr.New(apperr.CodeConfig, "credentials", apperr.RetryNever, "logout user ID is required")
	}
	result.LogoutUserID, err = readSecret(logoutPath)
	if err != nil {
		return Values{}, secretError("logout user ID", err)
	}
	if cfg.Socks.Enabled && (hasRemoteListener(cfg) || !cfg.Socks.AllowLoopbackNoAuth) {
		if socksPath == "" {
			return Values{}, apperr.New(apperr.CodeConfig, "credentials", apperr.RetryNever, "SOCKS password is required")
		}
		result.SocksPassword, err = readSecret(socksPath)
		if err != nil {
			return Values{}, secretError("SOCKS password", err)
		}
	}
	if len(result.VPNPassword) == 0 || len(result.LogoutUserID) == 0 {
		return Values{}, apperr.New(apperr.CodeConfig, "credentials", apperr.RetryNever, "required credential is empty")
	}
	if len(result.SocksPassword) > 255 {
		return Values{}, apperr.New(apperr.CodeConfig, "credentials", apperr.RetryNever, "SOCKS password exceeds RFC 1929 limit")
	}
	loaded = true
	return result, nil
}

func (v *Values) Clear() {
	clear(v.VPNPassword)
	clear(v.LogoutUserID)
	clear(v.SocksPassword)
	v.VPNPassword = nil
	v.LogoutUserID = nil
	v.SocksPassword = nil
}

func readSecret(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("credential is not a regular file")
	}
	if info.Mode().Perm()&0o007 != 0 {
		return nil, errors.New("credential is accessible by other users")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSecretBytes {
		return nil, errors.New("credential exceeds size limit")
	}
	if len(data) >= 2 && data[len(data)-2] == '\r' && data[len(data)-1] == '\n' {
		data = data[:len(data)-2]
	} else if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	return data, nil
}

func choose(values ...string) (string, bool) {
	for i, value := range values {
		if value != "" {
			return value, i < 2
		}
	}
	return "", false
}

func credentialPath(name string) string {
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory == "" {
		return ""
	}
	return filepath.Join(directory, name)
}

func secretError(kind string, err error) error {
	return apperr.Wrap(apperr.CodeConfig, "credentials", apperr.RetryNever, "cannot read "+kind, err)
}

func hasRemoteListener(cfg config.Config) bool {
	for _, raw := range cfg.Socks.Listeners {
		if !strings.HasPrefix(raw, "127.") {
			return true
		}
	}
	return false
}
