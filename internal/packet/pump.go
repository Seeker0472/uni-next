package packet

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/seeker/univpn/internal/apperr"
	"github.com/seeker/univpn/internal/network"
	protocol "github.com/seeker/univpn/internal/protocol/univpn"
)

type Pump struct {
	Connection        net.Conn
	Device            network.PacketDevice
	Session           protocol.SessionID
	MTU               int
	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
	WriteTimeout      time.Duration
	OnHeartbeat       func(time.Time)
}

func (p *Pump) Run(ctx context.Context, ready chan<- struct{}) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsCh := make(chan error, 3)
	var workers sync.WaitGroup
	var writeMu sync.Mutex
	var lastHeartbeat atomic.Int64
	lastHeartbeat.Store(time.Now().UnixNano())
	var readyOnce sync.Once
	frameBuffer := make([]byte, protocol.HeaderSize+p.MTU)
	writeFrame := func(kind uint16, body []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := p.Connection.SetWriteDeadline(time.Now().Add(p.WriteTimeout)); err != nil {
			return err
		}
		packet, err := protocol.EncodeInto(frameBuffer, p.Session, kind, body)
		if err != nil {
			return err
		}
		return writeAll(p.Connection, packet)
	}
	workers.Add(3)
	go func() { defer workers.Done(); errorsCh <- p.readLoop(runCtx, &lastHeartbeat, &readyOnce, ready) }()
	go func() { defer workers.Done(); errorsCh <- p.writeLoop(runCtx, writeFrame) }()
	go func() { defer workers.Done(); errorsCh <- p.heartbeatLoop(runCtx, &lastHeartbeat, writeFrame) }()
	err := <-errorsCh
	cancel()
	_ = p.Connection.SetDeadline(time.Now())
	workers.Wait()
	if err == nil || errors.Is(err, context.Canceled) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	return err
}

func (p *Pump) readLoop(ctx context.Context, last *atomic.Int64, readyOnce *sync.Once, ready chan<- struct{}) error {
	codec := protocol.NewCodec()
	scratch := make([]byte, 65535)
	for {
		if err := p.Connection.SetReadDeadline(time.Now().Add(p.HeartbeatTimeout)); err != nil {
			return err
		}
		frame, err := codec.ReadInto(p.Connection, &p.Session, scratch)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return apperr.Wrap(apperr.CodeTransient, "data_read", apperr.RetryNetwork, "tunnel read failed", err)
		}
		switch frame.Type {
		case protocol.TypeData:
			if err := ValidateIPv4(frame.Body, p.MTU, false); err != nil {
				return apperr.Wrap(apperr.CodeUnsupported, "data_read", apperr.RetryNever, "gateway sent an invalid IPv4 packet", err)
			}
			count, err := p.Device.WriteContext(ctx, frame.Body)
			if err != nil {
				return apperr.Wrap(apperr.CodeNetwork, "tun_write", apperr.RetryNever, "write to TUN failed", err)
			}
			if count != len(frame.Body) {
				return apperr.New(apperr.CodeNetwork, "tun_write", apperr.RetryNever, "TUN accepted only part of an IPv4 packet")
			}
		case protocol.TypeKeepalive:
			if len(frame.Body) != 0 {
				return apperr.New(apperr.CodeUnsupported, "heartbeat", apperr.RetryNever, "gateway returned a non-empty base keepalive")
			}
			now := time.Now()
			last.Store(now.UnixNano())
			if p.OnHeartbeat != nil {
				p.OnHeartbeat(now)
			}
			readyOnce.Do(func() { close(ready) })
		case protocol.TypeKickout:
			return apperr.New(apperr.CodeKickout, "data_read", apperr.RetryKickout, "gateway terminated the session")
		default:
			return apperr.New(apperr.CodeUnsupported, "data_read", apperr.RetryNever, "gateway sent an unsupported CNEM message")
		}
	}
}

func (p *Pump) writeLoop(ctx context.Context, writeFrame func(uint16, []byte) error) error {
	buffer := make([]byte, p.MTU)
	for {
		count, err := p.Device.ReadContext(ctx, buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return apperr.Wrap(apperr.CodeNetwork, "tun_read", apperr.RetryNever, "read from TUN failed", err)
		}
		packet := buffer[:count]
		if err := ValidateIPv4(packet, p.MTU, true); err != nil {
			continue
		}
		if err := writeFrame(protocol.TypeData, packet); err != nil {
			return apperr.Wrap(apperr.CodeTransient, "data_write", apperr.RetryNetwork, "tunnel write failed", err)
		}
	}
}

func (p *Pump) heartbeatLoop(ctx context.Context, last *atomic.Int64, writeFrame func(uint16, []byte) error) error {
	ticker := time.NewTicker(p.HeartbeatInterval)
	defer ticker.Stop()
	send := func() error { return writeFrame(protocol.TypeKeepalive, nil) }
	if err := send(); err != nil {
		return apperr.Wrap(apperr.CodeTransient, "heartbeat", apperr.RetryNetwork, "initial keepalive failed", err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			if now.Sub(time.Unix(0, last.Load())) > p.HeartbeatTimeout {
				return apperr.New(apperr.CodeTransient, "heartbeat", apperr.RetryNetwork, "gateway keepalive timed out")
			}
			if err := send(); err != nil {
				return apperr.Wrap(apperr.CodeTransient, "heartbeat", apperr.RetryNetwork, "keepalive write failed", err)
			}
		}
	}
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrUnexpectedEOF
		}
		value = value[count:]
	}
	return nil
}
