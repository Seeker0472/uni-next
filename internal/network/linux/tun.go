//go:build linux

package linux

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type Tun struct {
	file *os.File
	name string
}

func openTun(name string) (*Tun, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		file.Close()
		return nil, err
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, request); err != nil {
		file.Close()
		return nil, err
	}
	if err := unix.SetNonblock(int(file.Fd()), true); err != nil {
		file.Close()
		return nil, err
	}
	return &Tun{file: file, name: name}, nil
}

func (t *Tun) Name() string { return t.name }
func (t *Tun) Close() error { return t.file.Close() }
func (t *Tun) ReadContext(ctx context.Context, buffer []byte) (int, error) {
	return t.ioContext(ctx, buffer, true)
}
func (t *Tun) WriteContext(ctx context.Context, buffer []byte) (int, error) {
	return t.ioContext(ctx, buffer, false)
}

func (t *Tun) ioContext(ctx context.Context, buffer []byte, read bool) (int, error) {
	events := int16(unix.POLLOUT)
	if read {
		events = unix.POLLIN
	}
	fd := int(t.file.Fd())
	poll := []unix.PollFd{{Fd: int32(fd), Events: events}}
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		ready, err := unix.Poll(poll, 250)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, err
		}
		if ready == 0 {
			continue
		}
		var count int
		if read {
			count, err = unix.Read(fd, buffer)
		} else {
			count, err = unix.Write(fd, buffer)
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		return count, err
	}
}
