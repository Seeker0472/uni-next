// Package socks5 implements an authenticated, VPN-route-restricted SOCKS5 server.
package socks5

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/seeker/uni-next/internal/apperr"
	"github.com/seeker/uni-next/internal/config"
	genstate "github.com/seeker/uni-next/internal/generation"
	"github.com/seeker/uni-next/internal/proxy"
)

type Server struct {
	cfg            config.Socks
	gate           *genstate.Gate
	password       []byte
	allowedSources []netip.Prefix
	policy         *proxy.Policy
	sem            chan struct{}
	udpSem         chan struct{}
	mu             sync.Mutex
	perSource      map[netip.Addr]int
	handlers       sync.WaitGroup
}

func New(cfg config.Config, password []byte, gate *genstate.Gate) (*Server, error) {
	sources, err := prefixes(cfg.Socks.AllowSources)
	if err != nil {
		return nil, err
	}
	policy, err := proxy.NewPolicy(cfg.Socks.AllowedDestinations, cfg.Network.AllowedRoutes)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg.Socks, gate: gate, password: slices.Clone(password), allowedSources: sources, policy: policy, sem: make(chan struct{}, cfg.Socks.MaxTCPConnections), udpSem: make(chan struct{}, cfg.Socks.UDP.MaxAssociations), perSource: make(map[netip.Addr]int)}, nil
}

func (s *Server) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer clear(s.password)
	if !s.cfg.Enabled {
		defer cancel()
		<-runCtx.Done()
		return runCtx.Err()
	}
	listeners, err := s.listenAll(runCtx)
	if err != nil {
		cancel()
		return apperr.Wrap(apperr.CodeConfig, "socks_listen", apperr.RetryNever, "cannot bind configured SOCKS listeners", err)
	}
	errCh := make(chan error, len(listeners))
	var workers sync.WaitGroup
	defer func() {
		cancel()
		for _, listener := range listeners {
			listener.Close()
		}
		workers.Wait()
		s.handlers.Wait()
	}()
	for _, listener := range listeners {
		workers.Add(1)
		go func(value net.Listener) { defer workers.Done(); errCh <- s.acceptLoop(runCtx, value) }(listener)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (s *Server) listenAll(ctx context.Context) ([]net.Listener, error) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		listeners := make([]net.Listener, 0, len(s.cfg.Listeners))
		var failed error
		for _, address := range s.cfg.Listeners {
			listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", address)
			if err != nil {
				failed = err
				break
			}
			listeners = append(listeners, listener)
		}
		if failed == nil {
			return listeners, nil
		}
		for _, listener := range listeners {
			listener.Close()
		}
		if time.Now().After(deadline) {
			return nil, failed
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (s *Server) acceptLoop(ctx context.Context, listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return err
		}
		remote, ok := addrPort(connection.RemoteAddr())
		if !ok || !s.sourceAllowed(remote.Addr()) || !s.acquire(remote.Addr()) {
			connection.Close()
			continue
		}
		s.handlers.Add(1)
		go func() {
			defer s.handlers.Done()
			defer s.release(remote.Addr())
			defer connection.Close()
			stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
			defer stop()
			_ = s.handle(ctx, connection, remote.Addr())
		}()
	}
}

func (s *Server) handle(parent context.Context, connection net.Conn, source netip.Addr) error {
	if err := connection.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout.Duration)); err != nil {
		return err
	}
	methods, err := readMethods(connection)
	if err != nil {
		return err
	}
	noAuth := source.IsLoopback() && s.cfg.AllowLoopbackNoAuth && contains(methods, methodNoAuth)
	method := byte(methodUserPassword)
	if noAuth {
		method = methodNoAuth
	} else if !contains(methods, methodUserPassword) {
		_ = writeMethod(connection, methodNoAcceptable)
		return errors.New("client offered no acceptable authentication method")
	}
	if err := writeMethod(connection, method); err != nil {
		return err
	}
	if method == methodUserPassword {
		username, password, err := readUserPassword(connection)
		if err != nil {
			return err
		}
		valid := subtle.ConstantTimeCompare([]byte(username), []byte(s.cfg.Auth.Username)) & subtle.ConstantTimeCompare(password, s.password)
		clear(password)
		if err := writeUserPasswordStatus(connection, valid == 1); err != nil {
			return err
		}
		if valid != 1 {
			return errors.New("SOCKS authentication failed")
		}
	}
	command, target, err := readRequest(connection)
	if err != nil {
		_ = writeReply(connection, 1, netip.AddrPort{})
		return err
	}
	if target.port == 0 && command == commandConnect {
		_ = writeReply(connection, 8, netip.AddrPort{})
		return errors.New("CONNECT target port is zero")
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return err
	}
	switch command {
	case commandConnect:
		return s.connect(parent, connection, target)
	case commandUDPAssociate:
		if !s.cfg.UDP.Enabled {
			_ = writeReply(connection, 7, netip.AddrPort{})
			return errors.New("UDP ASSOCIATE is disabled")
		}
		select {
		case s.udpSem <- struct{}{}:
			defer func() { <-s.udpSem }()
			return s.udpAssociate(parent, connection, source, target)
		default:
			_ = writeReply(connection, 1, netip.AddrPort{})
			return errors.New("UDP association limit reached")
		}
	case commandBind:
		_ = writeReply(connection, 7, netip.AddrPort{})
		return errors.New("SOCKS BIND is unsupported")
	default:
		_ = writeReply(connection, 7, netip.AddrPort{})
		return errors.New("unsupported SOCKS command")
	}
}

func (s *Server) connect(parent context.Context, client net.Conn, target address) error {
	generation, err := s.gate.Acquire()
	if err != nil {
		_ = writeReply(client, 1, netip.AddrPort{})
		return err
	}
	ctx, cancel := proxy.LinkedContext(parent, generation.Context)
	defer cancel()
	upstream, err := s.policy.Dial(ctx, generation, target.host, target.port, s.cfg.DialTimeout.Duration)
	if err != nil {
		_ = writeReply(client, replyFor(err), netip.AddrPort{})
		return err
	}
	defer upstream.Close()
	bound, _ := addrPort(upstream.LocalAddr())
	if err := writeReply(client, 0, bound); err != nil {
		return err
	}
	return proxy.RelayTCP(ctx, client, upstream, s.cfg.TCPIdleTimeout.Duration)
}

func (s *Server) resolveAuthorized(ctx context.Context, generation genstate.Generation, target address) (netip.AddrPort, error) {
	return s.policy.Resolve(ctx, generation, target.host, target.port)
}

func (s *Server) sourceAllowed(address netip.Addr) bool {
	if len(s.allowedSources) == 0 {
		return address.IsLoopback()
	}
	return containsIP(s.allowedSources, address)
}
func containsIP(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
func prefixes(values []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func (s *Server) acquire(source netip.Addr) bool {
	select {
	case s.sem <- struct{}{}:
	default:
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perSource[source] >= s.cfg.MaxPerSource {
		<-s.sem
		return false
	}
	s.perSource[source]++
	return true
}
func (s *Server) release(source netip.Addr) {
	s.mu.Lock()
	s.perSource[source]--
	if s.perSource[source] == 0 {
		delete(s.perSource, source)
	}
	s.mu.Unlock()
	<-s.sem
}

func replyFor(err error) byte {
	var op *net.OpError
	if errors.As(err, &op) {
		if op.Timeout() {
			return 6
		}
	}
	return 5
}
