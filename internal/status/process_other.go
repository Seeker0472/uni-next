//go:build !linux

package status

import "errors"

func processIdentity(int) (string, error) {
	return "", errors.New("process status is only supported on Linux")
}
