// Package proxy provides shared target policy and relay primitives for local proxies.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	genstate "github.com/seeker/uni-next/internal/generation"
)

type Policy struct {
	allowed []netip.Prefix
}

func NewPolicy(configured, fallback []string) (*Policy, error) {
	values := configured
	if len(values) == 0 {
		values = fallback
	}
	allowed := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, prefix.Masked())
	}
	return &Policy{allowed: allowed}, nil
}

func (p *Policy) Resolve(ctx context.Context, generation genstate.Generation, host string, port uint16) (netip.AddrPort, error) {
	if port == 0 {
		return netip.AddrPort{}, errors.New("target port is zero")
	}
	var candidates []netip.Addr
	if parsed, err := netip.ParseAddr(host); err == nil {
		if !parsed.Is4() {
			return netip.AddrPort{}, errors.New("IPv6 target is unsupported")
		}
		candidates = []netip.Addr{parsed}
	} else {
		values, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			return netip.AddrPort{}, err
		}
		for _, value := range values {
			if value.Is4() {
				candidates = append(candidates, value)
			}
		}
	}
	if len(candidates) == 0 {
		return netip.AddrPort{}, errors.New("target has no IPv4 address")
	}
	for _, candidate := range candidates {
		if !p.allowedDestination(candidate, generation.Routes) {
			return netip.AddrPort{}, fmt.Errorf("target %s is outside active VPN routes", candidate)
		}
	}
	return netip.AddrPortFrom(candidates[0], port), nil
}

func (p *Policy) Dial(ctx context.Context, generation genstate.Generation, host string, port uint16, timeout time.Duration) (net.Conn, error) {
	if generation.Egress == nil {
		return nil, errors.New("VPN generation has no egress")
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	destination, err := p.Resolve(dialCtx, generation, host, port)
	if err != nil {
		return nil, err
	}
	return generation.Egress.DialTCP(dialCtx, destination)
}

func (p *Policy) allowedDestination(address netip.Addr, active []netip.Prefix) bool {
	if !address.Is4() || address.IsLoopback() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	return containsIP(p.allowed, address) && containsIP(active, address)
}

func containsIP(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func LinkedContext(left, right context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(left)
	stop := context.AfterFunc(right, cancel)
	return ctx, func() { stop(); cancel() }
}

var relayBuffers = sync.Pool{New: func() any { return make([]byte, 32<<10) }}

func RelayTCP(ctx context.Context, left, right net.Conn, idle time.Duration) error {
	type closeWriter interface{ CloseWrite() error }
	errorsCh := make(chan error, 2)
	copyDirection := func(destination, source net.Conn) {
		buffer := relayBuffers.Get().([]byte)
		_, err := io.CopyBuffer(activityWriter{Conn: destination, idle: idle}, activityReader{Conn: source, idle: idle}, buffer)
		relayBuffers.Put(buffer)
		if value, ok := destination.(closeWriter); ok {
			_ = value.CloseWrite()
		}
		errorsCh <- err
	}
	go copyDirection(right, left)
	go copyDirection(left, right)
	select {
	case <-ctx.Done():
		_ = left.Close()
		_ = right.Close()
		<-errorsCh
		<-errorsCh
		return ctx.Err()
	case first := <-errorsCh:
		second := <-errorsCh
		return errors.Join(first, second)
	}
}

type activityReader struct {
	net.Conn
	idle time.Duration
}

func (c activityReader) Read(value []byte) (int, error) {
	if c.idle > 0 {
		_ = c.SetReadDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Read(value)
}

type activityWriter struct {
	net.Conn
	idle time.Duration
}

func (c activityWriter) Write(value []byte) (int, error) {
	if c.idle > 0 {
		_ = c.SetWriteDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Write(value)
}
