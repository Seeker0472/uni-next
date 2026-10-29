package socks5

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	genstate "github.com/seeker/uni-next/internal/generation"
	proxycore "github.com/seeker/uni-next/internal/proxy"
)

func (s *Server) udpAssociate(parent context.Context, control net.Conn, sourceIP netip.Addr, requested address) error {
	generation, err := s.gate.Acquire()
	if err != nil {
		_ = writeReply(control, 1, netip.AddrPort{})
		return err
	}
	ctx, cancel := proxycore.LinkedContext(parent, generation.Context)
	defer cancel()
	local, ok := addrPort(control.LocalAddr())
	if !ok || !local.Addr().Is4() {
		_ = writeReply(control, 1, netip.AddrPort{})
		return errors.New("invalid SOCKS listener address")
	}
	relay, bound, err := s.bindUDPRelay(local.Addr())
	if err != nil {
		_ = writeReply(control, 1, netip.AddrPort{})
		return err
	}
	defer relay.Close()
	if generation.Egress == nil {
		_ = writeReply(control, 1, netip.AddrPort{})
		return errors.New("VPN generation has no egress")
	}
	upstream, err := generation.Egress.ListenUDP()
	if err != nil {
		_ = writeReply(control, 1, netip.AddrPort{})
		return err
	}
	defer upstream.Close()
	if err := writeReply(control, 0, bound); err != nil {
		return err
	}
	association := &udpAssociation{server: s, generation: generation, relay: relay, upstream: upstream, sourceIP: sourceIP, remotes: make(map[netip.AddrPort]struct{})}
	if parsed, err := netip.ParseAddr(requested.host); err == nil && parsed.Is4() && !parsed.IsUnspecified() {
		association.client = netip.AddrPortFrom(parsed, requested.port)
	} else if requested.port != 0 {
		association.client = netip.AddrPortFrom(sourceIP, requested.port)
	}
	association.lastActivity.Store(time.Now().UnixNano())
	errCh := make(chan error, 3)
	go func() { var one [1]byte; _, err := control.Read(one[:]); errCh <- err }()
	go func() { errCh <- association.clientLoop(ctx) }()
	go func() { errCh <- association.remoteLoop(ctx) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if err == nil {
				return nil
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		case now := <-ticker.C:
			if now.Sub(time.Unix(0, association.lastActivity.Load())) > s.cfg.UDP.IdleTimeout.Duration {
				return nil
			}
		}
	}
}

type udpAssociation struct {
	server       *Server
	generation   genstate.Generation
	relay        *net.UDPConn
	upstream     net.PacketConn
	sourceIP     netip.Addr
	client       netip.AddrPort
	clientMu     sync.RWMutex
	remotes      map[netip.AddrPort]struct{}
	remotesMu    sync.RWMutex
	lastActivity atomic.Int64
}

func (a *udpAssociation) clientLoop(ctx context.Context) error {
	buffer := make([]byte, 65535)
	for {
		if err := a.relay.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		count, source, err := a.relay.ReadFromUDPAddrPort(buffer)
		if timeout(err) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if err != nil {
			return err
		}
		if !a.acceptClient(source) {
			continue
		}
		target, payload, err := parseUDPRequest(buffer[:count])
		if err != nil {
			continue
		}
		destination, err := a.server.resolveAuthorized(ctx, a.generation, target)
		if err != nil {
			continue
		}
		if !a.allowRemote(destination) {
			continue
		}
		if _, err := a.upstream.WriteTo(payload, net.UDPAddrFromAddrPort(destination)); err != nil {
			return err
		}
		a.lastActivity.Store(time.Now().UnixNano())
	}
}

func (a *udpAssociation) remoteLoop(ctx context.Context) error {
	buffer := make([]byte, 65535)
	response := make([]byte, 65545)
	for {
		if err := a.upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		count, rawSource, err := a.upstream.ReadFrom(buffer)
		if timeout(err) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if err != nil {
			return err
		}
		source, ok := addrPort(rawSource)
		if !ok {
			continue
		}
		a.remotesMu.RLock()
		_, allowed := a.remotes[source]
		a.remotesMu.RUnlock()
		if !allowed {
			continue
		}
		a.clientMu.RLock()
		client := a.client
		a.clientMu.RUnlock()
		if !client.IsValid() {
			continue
		}
		packet, err := encodeUDPResponse(source, buffer[:count], response)
		if err != nil {
			continue
		}
		if _, err := a.relay.WriteToUDPAddrPort(packet, client); err != nil {
			return err
		}
		a.lastActivity.Store(time.Now().UnixNano())
	}
}

func (a *udpAssociation) acceptClient(source netip.AddrPort) bool {
	if source.Addr() != a.sourceIP {
		return false
	}
	a.clientMu.Lock()
	defer a.clientMu.Unlock()
	if !a.client.IsValid() || a.client.Port() == 0 {
		a.client = source
		return true
	}
	return source == a.client
}

func (a *udpAssociation) allowRemote(value netip.AddrPort) bool {
	a.remotesMu.Lock()
	defer a.remotesMu.Unlock()
	if _, exists := a.remotes[value]; exists {
		return true
	}
	if len(a.remotes) >= a.server.cfg.UDP.MaxRemotesPerAssociation {
		return false
	}
	a.remotes[value] = struct{}{}
	return true
}

func (s *Server) bindUDPRelay(address netip.Addr) (*net.UDPConn, netip.AddrPort, error) {
	first := int(s.cfg.UDP.PortRange.From)
	for offset := range int(s.cfg.UDP.PortRange.To) - first + 1 {
		port := first + offset
		connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(address.AsSlice()), Port: port})
		if err != nil {
			continue
		}
		bound, _ := addrPort(connection.LocalAddr())
		return connection, bound, nil
	}
	return nil, netip.AddrPort{}, errors.New("SOCKS UDP relay port range is exhausted")
}

func timeout(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
