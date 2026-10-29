// Package httpproxy implements a route-restricted local HTTP/1.1 forward proxy.
package httpproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/seeker/uni-next/internal/config"
	genstate "github.com/seeker/uni-next/internal/generation"
	proxycore "github.com/seeker/uni-next/internal/proxy"
)

type Server struct {
	cfg       config.HTTP
	gate      *genstate.Gate
	policy    *proxycore.Policy
	sem       chan struct{}
	mu        sync.Mutex
	perSource map[netip.Addr]int
}

func New(cfg config.Config, gate *genstate.Gate) (*Server, error) {
	policy, err := proxycore.NewPolicy(cfg.HTTP.AllowedDestinations, cfg.Network.AllowedRoutes)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:       cfg.HTTP,
		gate:      gate,
		policy:    policy,
		sem:       make(chan struct{}, cfg.HTTP.MaxConnections),
		perSource: make(map[netip.Addr]int),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	if !s.cfg.Enabled {
		<-ctx.Done()
		return ctx.Err()
	}
	listeners := make([]net.Listener, 0, len(s.cfg.Listeners))
	for _, address := range s.cfg.Listeners {
		listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", address)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return err
		}
		listeners = append(listeners, &limitedListener{Listener: listener, server: s})
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	httpServer := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: s.cfg.ReadHeaderTimeout.Duration,
		IdleTimeout:       s.cfg.IdleTimeout.Duration,
		MaxHeaderBytes:    64 << 10,
		BaseContext:       func(net.Listener) context.Context { return runCtx },
	}
	errCh := make(chan error, len(listeners))
	var workers sync.WaitGroup
	for _, listener := range listeners {
		workers.Add(1)
		go func(value net.Listener) {
			defer workers.Done()
			errCh <- httpServer.Serve(value)
		}(listener)
	}
	defer func() {
		cancel()
		_ = httpServer.Close()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		workers.Wait()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect {
		s.serveConnect(writer, request)
		return
	}
	s.serveForward(writer, request)
}

func (s *Server) serveConnect(writer http.ResponseWriter, request *http.Request) {
	host, port, err := target(request.Host, "")
	if err != nil {
		http.Error(writer, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	generation, err := s.gate.Acquire()
	if err != nil {
		http.Error(writer, "VPN is not ready", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := proxycore.LinkedContext(request.Context(), generation.Context)
	defer cancel()
	upstream, err := s.policy.Dial(ctx, generation, host, port, s.cfg.DialTimeout.Duration)
	if err != nil {
		http.Error(writer, "target unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "CONNECT is unsupported", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	connection := net.Conn(client)
	if buffered.Reader.Buffered() != 0 {
		connection = &bufferedConn{Conn: client, reader: buffered.Reader}
	}
	_ = proxycore.RelayTCP(ctx, connection, upstream, s.cfg.IdleTimeout.Duration)
}

func (s *Server) serveForward(writer http.ResponseWriter, request *http.Request) {
	if !request.URL.IsAbs() || !strings.EqualFold(request.URL.Scheme, "http") || request.URL.User != nil {
		http.Error(writer, "absolute http URL required", http.StatusBadRequest)
		return
	}
	generation, err := s.gate.Acquire()
	if err != nil {
		http.Error(writer, "VPN is not ready", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := proxycore.LinkedContext(request.Context(), generation.Context)
	defer cancel()

	outbound := request.Clone(ctx)
	outbound.RequestURI = ""
	outbound.Close = true
	removeHopHeaders(outbound.Header)
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: s.cfg.ReadHeaderTimeout.Duration,
		DialContext: func(dialCtx context.Context, _, address string) (net.Conn, error) {
			host, port, err := target(address, "80")
			if err != nil {
				return nil, err
			}
			return s.policy.Dial(dialCtx, generation, host, port, s.cfg.DialTimeout.Duration)
		},
	}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(outbound)
	if err != nil {
		http.Error(writer, "target unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	removeHopHeaders(response.Header)
	copyHeaders(writer.Header(), response.Header)
	writer.WriteHeader(response.StatusCode)
	_, _ = io.Copy(writer, response.Body)
}

func target(authority, defaultPort string) (string, uint16, error) {
	host, rawPort, err := net.SplitHostPort(authority)
	if err != nil {
		if defaultPort == "" || strings.Contains(authority, ":") {
			return "", 0, err
		}
		host, rawPort = authority, defaultPort
	}
	if host == "" {
		return "", 0, errors.New("target host is empty")
	}
	value, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || value == 0 {
		return "", 0, fmt.Errorf("invalid target port %q", rawPort)
	}
	return host, uint16(value), nil
}

var hopHeaders = [...]string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopHeaders {
		header.Del(name)
	}
}

func copyHeaders(destination, source http.Header) {
	for name, values := range source {
		for _, value := range values {
			destination.Add(name, value)
		}
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(destination []byte) (int, error) {
	return c.reader.Read(destination)
}

func (c *bufferedConn) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

type limitedListener struct {
	net.Listener
	server *Server
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		remote, ok := addrPort(connection.RemoteAddr())
		if !ok || !remote.Addr().IsLoopback() || !l.server.acquire(remote.Addr()) {
			_ = connection.Close()
			continue
		}
		return &trackedConn{Conn: connection, release: func() { l.server.release(remote.Addr()) }}, nil
	}
}

type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (c *trackedConn) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
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

func addrPort(address net.Addr) (netip.AddrPort, bool) {
	value, err := netip.ParseAddrPort(address.String())
	return value, err == nil
}
