package credential

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/seeker/univpn/internal/config"
)

func TestLoadUsesSystemdCredentialsAndClearsSecrets(t *testing.T) {
	directory := t.TempDir()
	writeCredential(t, directory, "vpn-password", []byte("vpn-secret\r\n"), 0o600)
	writeCredential(t, directory, "logout-user-id", []byte("operator-id\n"), 0o600)
	t.Setenv("CREDENTIALS_DIRECTORY", directory)

	values, err := Load(config.Defaults(), Overrides{}, nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if string(values.VPNPassword) != "vpn-secret" || string(values.LogoutUserID) != "operator-id" {
		t.Fatalf("unexpected credential values: vpn=%q logout=%q", values.VPNPassword, values.LogoutUserID)
	}
	vpnStorage := values.VPNPassword
	logoutStorage := values.LogoutUserID
	values.Clear()
	if !allZero(vpnStorage) || !allZero(logoutStorage) {
		t.Fatal("credential backing storage was not cleared")
	}
}

func TestReadSecretRejectsWorldAccessibleFile(t *testing.T) {
	directory := t.TempDir()
	path := writeCredential(t, directory, "unsafe", []byte("secret"), 0o604)
	if _, err := readSecret(path); err == nil {
		t.Fatal("world-accessible credential was accepted")
	}
}

func writeCredential(t *testing.T, directory, name string, value []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func allZero(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}
