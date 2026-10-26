//go:build !linux

package session

import "errors"

type InstanceLock struct{}

func AcquireLock(string) (*InstanceLock, error) {
	return nil, errors.New("univpn is only supported on Linux")
}
func (*InstanceLock) Close() error { return nil }
