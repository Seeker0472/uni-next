package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/seeker/uni-next/internal/apperr"
	"github.com/seeker/uni-next/internal/config"
	"github.com/seeker/uni-next/internal/credential"
	genstate "github.com/seeker/uni-next/internal/generation"
	"github.com/seeker/uni-next/internal/httpproxy"
	"github.com/seeker/uni-next/internal/network"
	networklinux "github.com/seeker/uni-next/internal/network/linux"
	"github.com/seeker/uni-next/internal/packet"
	protocol "github.com/seeker/uni-next/internal/protocol/cnem"
	"github.com/seeker/uni-next/internal/socks5"
	"github.com/seeker/uni-next/internal/status"
	"github.com/seeker/uni-next/internal/transport"
	"github.com/seeker/uni-next/internal/usernet"
)

type Mode string

const (
	ModeSystem Mode = "system"
	ModeProxy  Mode = "proxy"
)

type Runtime struct {
	Config      config.Config
	Credentials credential.Values
	Logger      *slog.Logger
	Mode        Mode
}

func (r Runtime) Run(ctx context.Context) (returnErr error) {
	logger := r.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if r.Mode == "" {
		r.Mode = ModeSystem
	}
	if r.Mode != ModeSystem && r.Mode != ModeProxy {
		return apperr.New(apperr.CodeConfig, "preflight", apperr.RetryNever, "unsupported runtime mode")
	}
	lock, err := AcquireLock(r.Config.Runtime.RunDir)
	if err != nil {
		return apperr.Wrap(apperr.CodeConfig, "preflight", apperr.RetryNever, "acquire instance lock", err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil && returnErr == nil {
			returnErr = apperr.Wrap(apperr.CodeConfig, "shutdown", apperr.RetryNever, "release instance lock", closeErr)
		}
	}()
	store := status.NewStore(r.Config.Runtime.RunDir)
	updateStatus(logger, store, func(value *status.Snapshot) {
		value.Phase = "preflight"
		value.Mode = string(r.Mode)
	})
	var lease network.Lease
	if r.Mode == ModeProxy {
		if err := r.Config.ValidateProxyMode(); err != nil {
			return apperr.Wrap(apperr.CodeConfig, "preflight", apperr.RetryNever, "invalid proxy mode configuration", err)
		}
		lease = usernet.New(r.Config.Network.MTU)
	} else {
		protected, err := network.ProtectionPlan(r.Config)
		if err != nil {
			return apperr.Wrap(apperr.CodeConfig, "preflight", apperr.RetryNever, "build protection plan", err)
		}
		lease, err = networklinux.Prepare(ctx, r.Config, protected)
		if err != nil {
			return err
		}
	}
	defer func() {
		updateStatus(logger, store, func(value *status.Snapshot) {
			value.Phase = "stopping"
			value.SocksReady = false
			value.HTTPReady = false
		})
		if closeErr := lease.Close(); closeErr != nil {
			if returnErr == nil {
				returnErr = closeErr
			} else {
				returnErr = apperr.Wrap(apperr.CodeNetwork, "cleanup", apperr.RetryNever, "network cleanup was incomplete", errors.Join(returnErr, closeErr))
			}
		}
	}()
	updateStatus(logger, store, func(value *status.Snapshot) { value.Phase = "guarded" })
	dialer, err := transport.NewDialer(r.Config)
	if err != nil {
		return err
	}
	client := protocol.NewClient(r.Config, dialer.Dial)
	gate := &genstate.Gate{}
	socksProxy, err := socks5.New(r.Config, r.Credentials.SocksPassword, gate)
	if err != nil {
		return apperr.Wrap(apperr.CodeConfig, "socks", apperr.RetryNever, "initialize SOCKS server", err)
	}
	httpProxy, err := httpproxy.New(r.Config, gate)
	if err != nil {
		return apperr.Wrap(apperr.CodeConfig, "http", apperr.RetryNever, "initialize HTTP proxy", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	serviceErr := make(chan error, 2)
	var services sync.WaitGroup
	startService := func(stage string, run func(context.Context) error) {
		services.Add(1)
		go func() {
			defer services.Done()
			if err := run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
				select {
				case serviceErr <- apperr.Wrap(apperr.CodeConfig, stage, apperr.RetryNever, stage+" service stopped", err):
				default:
				}
				cancel()
			}
		}()
	}
	startService("socks", socksProxy.Run)
	startService("http", httpProxy.Run)
	defer func() {
		cancel()
		services.Wait()
	}()
	budget := NewKickoutBudget(r.Config.Reconnect.Kickout.Mode, r.Config.Reconnect.Kickout.Window.Duration, r.Config.Reconnect.Kickout.MaxRetries)
	backoff := NewBackoff(r.Config.Reconnect.Initial.Duration, r.Config.Reconnect.Maximum.Duration)
	var generation uint64
	for {
		if err := runCtx.Err(); err != nil {
			if proxyErr := nonblockingError(serviceErr); proxyErr != nil {
				return proxyErr
			}
			return apperr.New(apperr.CodeCanceled, "shutdown", apperr.RetryNever, "shutdown requested")
		}
		result := r.runGeneration(runCtx, client, lease, gate, store, logger, generation+1)
		generation++
		if proxyErr := nonblockingError(serviceErr); proxyErr != nil {
			return proxyErr
		}
		if result.Err == nil || errors.Is(result.Err, context.Canceled) {
			if ctx.Err() != nil {
				return apperr.New(apperr.CodeCanceled, "shutdown", apperr.RetryNever, "shutdown requested")
			}
			result.Err = apperr.New(apperr.CodeTransient, "session", apperr.RetryNetwork, "session ended unexpectedly")
		}
		appErr, classified := apperr.As(result.Err)
		if !classified {
			return result.Err
		}
		updateStatus(logger, store, func(value *status.Snapshot) {
			value.LastErrorCode = string(appErr.Code)
			value.LastErrorStage = appErr.Stage
			value.LastError = appErr.Error()
		})
		if appErr.Retry == apperr.RetryKickout {
			if !budget.Allow(time.Now()) {
				return apperr.New(apperr.CodeKickout, "reconnect", apperr.RetryNever, "KICKOUT retry policy is exhausted")
			}
		} else if appErr.Retry != apperr.RetryNetwork {
			return result.Err
		} else if !r.Config.Reconnect.Network.Enabled {
			return apperr.Wrap(apperr.CodeNoReconnect, "reconnect", apperr.RetryNever, "network reconnect is disabled", result.Err)
		}
		if !result.ReadySince.IsZero() && time.Since(result.ReadySince) >= r.Config.Reconnect.ResetAfter.Duration {
			backoff.Reset()
		}
		delay := backoff.Next()
		logger.Warn("VPN session interrupted; reconnecting", "code", appErr.Code, "stage", appErr.Stage, "after", delay)
		updateStatus(logger, store, func(value *status.Snapshot) { value.Phase = "backoff"; value.Reconnects++; value.SocksReady = false })
		select {
		case <-runCtx.Done():
			continue
		case <-time.After(delay):
		}
	}
}

type generationResult struct {
	Err        error
	ReadySince time.Time
}

func (r Runtime) runGeneration(ctx context.Context, client *protocol.Client, lease network.Lease, gate *genstate.Gate, store *status.Store, logger *slog.Logger, generation uint64) generationResult {
	setPhase := func(phase string) {
		updateStatus(logger, store, func(value *status.Snapshot) { value.Phase = phase; value.Generation = generation })
	}
	setPhase("connecting")
	if err := client.FirstConnect(ctx); err != nil {
		return generationResult{Err: err}
	}
	setPhase("authenticating")
	auth, err := client.Authenticate(ctx, protocol.Identity{Username: r.Config.Auth.Username, Password: r.Credentials.VPNPassword, MAC: r.Config.Auth.MAC})
	if err != nil {
		return generationResult{Err: err}
	}
	setPhase("negotiating")
	negotiated, err := client.Negotiate(ctx, auth)
	if err != nil {
		r.logout(client, auth)
		return generationResult{Err: err}
	}
	if negotiated.Network.HasDNS {
		logger.Warn("gateway supplied DNS data; current profile intentionally does not apply it")
	}
	plan, err := network.BuildPlan(r.Config, negotiated.Network)
	if err != nil {
		negotiated.Connection.Close()
		r.logout(client, auth)
		return generationResult{Err: apperr.Wrap(apperr.CodeUnsupported, "netcfg", apperr.RetryNever, "negotiated routes do not satisfy policy", err)}
	}
	setPhase("configuring")
	if err := lease.Activate(ctx, plan); err != nil {
		negotiated.Connection.Close()
		r.logout(client, auth)
		return generationResult{Err: err}
	}
	egress := genstate.Egress(kernelEgress{vip: plan.VIP})
	if provider, ok := lease.(interface {
		Egress() (genstate.Egress, error)
	}); ok {
		egress, err = provider.Egress()
		if err != nil {
			_ = lease.Suspend(context.Background())
			negotiated.Connection.Close()
			r.logout(client, auth)
			return generationResult{Err: apperr.Wrap(apperr.CodeNetwork, "netcfg", apperr.RetryNever, "initialize proxy egress", err)}
		}
	}
	generationCtx, generationCancel := context.WithCancel(ctx)
	ready := make(chan struct{})
	pump := packet.Pump{Connection: negotiated.Connection, Device: lease.Device(), Session: auth.Session, MTU: r.Config.Network.MTU, HeartbeatInterval: r.Config.Heartbeat.Interval.Duration, HeartbeatTimeout: r.Config.Heartbeat.Timeout.Duration, WriteTimeout: r.Config.Timeouts.Write.Duration, OnHeartbeat: func(at time.Time) {
		updateStatus(logger, store, func(value *status.Snapshot) { value.LastHeartbeat = at.UTC() })
	}}
	pumpDone := make(chan error, 1)
	go func() { pumpDone <- pump.Run(generationCtx, ready) }()
	var readySince time.Time
	select {
	case <-ready:
		readySince = time.Now()
		gate.Set(genstate.Generation{ID: generation, Context: generationCtx, VIP: plan.VIP, Routes: plan.Routes, Interface: lease.Device().Name(), Egress: egress})
		routeStrings := make([]string, len(plan.Routes))
		for index, route := range plan.Routes {
			routeStrings[index] = route.String()
		}
		updateStatus(logger, store, func(value *status.Snapshot) {
			value.Phase = "ready"
			value.VIP = plan.VIP.String()
			value.Routes = routeStrings
			value.SocksReady = r.Config.Socks.Enabled
			value.HTTPReady = r.Config.HTTP.Enabled
			value.LastError = ""
			value.LastErrorCode = ""
			value.LastErrorStage = ""
		})
	case err := <-pumpDone:
		generationCancel()
		negotiated.Connection.Close()
		if suspendErr := lease.Suspend(context.Background()); suspendErr != nil {
			r.logout(client, auth)
			return generationResult{Err: suspendErr}
		}
		r.logout(client, auth)
		return generationResult{Err: err}
	case <-ctx.Done():
		generationCancel()
		negotiated.Connection.Close()
		<-pumpDone
		if err := lease.Suspend(context.Background()); err != nil {
			r.logout(client, auth)
			return generationResult{Err: err}
		}
		r.logout(client, auth)
		return generationResult{Err: ctx.Err()}
	}
	err = <-pumpDone
	gate.Clear(generation)
	generationCancel()
	negotiated.Connection.Close()
	setPhase("suspending")
	updateStatus(logger, store, func(snapshot *status.Snapshot) {
		snapshot.SocksReady = false
		snapshot.HTTPReady = false
		snapshot.VIP = ""
		snapshot.Routes = nil
	})
	if suspendErr := lease.Suspend(context.Background()); suspendErr != nil {
		r.logout(client, auth)
		return generationResult{Err: suspendErr, ReadySince: readySince}
	}
	r.logout(client, auth)
	return generationResult{Err: err, ReadySince: readySince}
}

func updateStatus(logger *slog.Logger, store *status.Store, mutate func(*status.Snapshot)) {
	if err := store.Update(mutate); err != nil {
		logger.Warn("status snapshot update failed", "error", err)
	}
}

func (r Runtime) logout(client *protocol.Client, auth protocol.Authentication) {
	ctx, cancel := context.WithTimeout(context.Background(), r.Config.Timeouts.Logout.Duration)
	defer cancel()
	if err := client.Logout(ctx, auth, r.Credentials.LogoutUserID); err != nil && r.Logger != nil {
		appErr, _ := apperr.As(err)
		if appErr != nil {
			r.Logger.Warn("logout was not confirmed", "code", appErr.Code, "stage", appErr.Stage)
		} else {
			r.Logger.Warn("logout was not confirmed")
		}
	}
}

func nonblockingError(channel <-chan error) error {
	select {
	case err := <-channel:
		return err
	default:
		return nil
	}
}

func (r Runtime) String() string { return fmt.Sprintf("uni-next runtime for %s", r.Config.Server.Host) }
