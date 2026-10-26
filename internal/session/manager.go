package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/seeker/univpn/internal/apperr"
	"github.com/seeker/univpn/internal/config"
	"github.com/seeker/univpn/internal/credential"
	genstate "github.com/seeker/univpn/internal/generation"
	"github.com/seeker/univpn/internal/network"
	networklinux "github.com/seeker/univpn/internal/network/linux"
	"github.com/seeker/univpn/internal/packet"
	protocol "github.com/seeker/univpn/internal/protocol/univpn"
	"github.com/seeker/univpn/internal/socks5"
	"github.com/seeker/univpn/internal/status"
	"github.com/seeker/univpn/internal/transport"
)

type Runtime struct {
	Config      config.Config
	Credentials credential.Values
	Logger      *slog.Logger
}

func (r Runtime) Run(ctx context.Context) (returnErr error) {
	logger := r.Logger
	if logger == nil {
		logger = slog.Default()
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
	updateStatus(logger, store, func(value *status.Snapshot) { value.Phase = "preflight" })
	protected, err := network.ProtectionPlan(r.Config)
	if err != nil {
		return apperr.Wrap(apperr.CodeConfig, "preflight", apperr.RetryNever, "build protection plan", err)
	}
	lease, err := networklinux.Prepare(ctx, r.Config, protected)
	if err != nil {
		return err
	}
	defer func() {
		updateStatus(logger, store, func(value *status.Snapshot) { value.Phase = "stopping"; value.SocksReady = false })
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
	proxy, err := socks5.New(r.Config, r.Credentials.SocksPassword, gate)
	if err != nil {
		return apperr.Wrap(apperr.CodeConfig, "socks", apperr.RetryNever, "initialize SOCKS server", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	socksErr := make(chan error, 1)
	socksDone := make(chan struct{})
	defer func() {
		cancel()
		<-socksDone
	}()
	go func() {
		defer close(socksDone)
		err := proxy.Run(runCtx)
		if err != nil && !errors.Is(err, context.Canceled) {
			socksErr <- err
			cancel()
		} else {
			socksErr <- nil
		}
	}()
	budget := NewKickoutBudget(r.Config.Reconnect.Kickout.Mode, r.Config.Reconnect.Kickout.Window.Duration, r.Config.Reconnect.Kickout.MaxRetries)
	backoff := NewBackoff(r.Config.Reconnect.Initial.Duration, r.Config.Reconnect.Maximum.Duration)
	var generation uint64
	for {
		if err := runCtx.Err(); err != nil {
			if proxyErr := nonblockingError(socksErr); proxyErr != nil {
				return apperr.Wrap(apperr.CodeConfig, "socks", apperr.RetryNever, "SOCKS service stopped", proxyErr)
			}
			return apperr.New(apperr.CodeCanceled, "shutdown", apperr.RetryNever, "shutdown requested")
		}
		result := r.runGeneration(runCtx, client, lease, gate, store, logger, generation+1)
		generation++
		if proxyErr := nonblockingError(socksErr); proxyErr != nil {
			return apperr.Wrap(apperr.CodeConfig, "socks", apperr.RetryNever, "SOCKS service stopped", proxyErr)
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
		} else if appErr.Retry != apperr.RetryNetwork || !r.Config.Reconnect.Network.Enabled {
			return result.Err
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
		gate.Set(genstate.Generation{ID: generation, Context: generationCtx, VIP: plan.VIP, Routes: plan.Routes, Interface: lease.Device().Name()})
		routeStrings := make([]string, len(plan.Routes))
		for index, route := range plan.Routes {
			routeStrings[index] = route.String()
		}
		updateStatus(logger, store, func(value *status.Snapshot) {
			value.Phase = "ready"
			value.VIP = plan.VIP.String()
			value.Routes = routeStrings
			value.SocksReady = r.Config.Socks.Enabled
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
	updateStatus(logger, store, func(snapshot *status.Snapshot) { snapshot.SocksReady = false; snapshot.VIP = ""; snapshot.Routes = nil })
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

func (r Runtime) String() string { return fmt.Sprintf("univpn runtime for %s", r.Config.Server.Host) }
