package network

import (
	"context"
	"io"
)

type PacketDevice interface {
	ReadContext(context.Context, []byte) (int, error)
	WriteContext(context.Context, []byte) (int, error)
	Name() string
}

type Lease interface {
	Device() PacketDevice
	Activate(context.Context, Plan) error
	Suspend(context.Context) error
	Close() error
}

type ClosedDevice interface{ io.Closer }
