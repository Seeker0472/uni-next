//go:build !linux

package linux

import (
	"context"
	"errors"
	"net/netip"

	"github.com/seeker/uni-next/internal/config"
	"github.com/seeker/uni-next/internal/network"
)

func Prepare(context.Context, config.Config, []netip.Prefix) (network.Lease, error) {
	return nil, errors.New("uni-next network backend only supports Linux")
}
