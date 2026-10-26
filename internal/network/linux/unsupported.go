//go:build !linux

package linux

import (
	"context"
	"errors"
	"net/netip"

	"github.com/seeker/univpn/internal/config"
	"github.com/seeker/univpn/internal/network"
)

func Prepare(context.Context, config.Config, []netip.Prefix) (network.Lease, error) {
	return nil, errors.New("univpn network backend only supports Linux")
}
