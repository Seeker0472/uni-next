//go:build linux

package linux

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/seeker/univpn/internal/apperr"
	"github.com/seeker/univpn/internal/config"
	"github.com/seeker/univpn/internal/network"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const routeProtocol = netlink.RouteProtocol(0xfd)

type journal struct {
	Owner        string   `json:"owner"`
	TunName      string   `json:"tun_name"`
	Table        int      `json:"table"`
	RulePriority int      `json:"rule_priority"`
	GuardRoutes  []string `json:"guard_routes"`
	Rules        []string `json:"rules"`
	ActiveRoutes []string `json:"active_routes,omitempty"`
	VIP          string   `json:"vip,omitempty"`
}

type Lease struct {
	mu          sync.Mutex
	cfg         config.Config
	tun         *Tun
	owner       string
	journalPath string
	guardRoutes []netip.Prefix
	rules       []netip.Prefix
	active      *network.Plan
}

func Prepare(ctx context.Context, cfg config.Config, protected []netip.Prefix) (_ network.Lease, returnErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	journalPath := filepath.Join(cfg.Runtime.StateDir, "network-state.json")
	if err := os.MkdirAll(cfg.Runtime.StateDir, 0o750); err != nil {
		return nil, networkError("prepare", "create state directory", err)
	}
	if err := recoverJournal(journalPath); err != nil {
		return nil, networkError("recovery", "recover previous network transaction", err)
	}
	if cfg.Network.RulePriority+len(protected) >= 32766 {
		return nil, networkError("prepare", "policy rule priority range is too small", nil)
	}
	owner, err := randomOwner()
	if err != nil {
		return nil, networkError("prepare", "create resource owner", err)
	}
	tun, err := openTun(cfg.Network.TunName)
	if err != nil {
		return nil, networkError("prepare", "create TUN device", err)
	}
	lease := &Lease{cfg: cfg, tun: tun, owner: owner, journalPath: journalPath}
	defer func() {
		if returnErr != nil {
			if cleanupErr := lease.Close(); cleanupErr != nil {
				returnErr = networkError("prepare", "rollback was incomplete", errors.Join(returnErr, cleanupErr))
			}
		}
	}()
	link, err := netlink.LinkByName(cfg.Network.TunName)
	if err != nil {
		return nil, networkError("prepare", "find created TUN device", err)
	}
	if err := netlink.LinkSetAlias(link, "univpn:"+owner); err != nil {
		return nil, networkError("prepare", "mark TUN ownership", err)
	}
	if err := lease.writeJournal(); err != nil {
		return nil, networkError("prepare", "record TUN ownership", err)
	}
	for index, prefix := range protected {
		route := guardRoute(cfg.Network.Table, prefix)
		if err := netlink.RouteAdd(&route); err != nil {
			return nil, networkError("prepare", "install unreachable protection for "+prefix.String(), err)
		}
		lease.guardRoutes = append(lease.guardRoutes, prefix)
		if err := lease.writeJournal(); err != nil {
			return nil, networkError("prepare", "record protected route", err)
		}
		rule := destinationRule(cfg.Network.Table, cfg.Network.RulePriority+index, prefix)
		if err := netlink.RuleAdd(&rule); err != nil {
			return nil, networkError("prepare", "install policy rule for "+prefix.String(), err)
		}
		lease.rules = append(lease.rules, prefix)
		if err := lease.writeJournal(); err != nil {
			return nil, networkError("prepare", "record protected rule", err)
		}
	}
	return lease, nil
}

func (l *Lease) Device() network.PacketDevice { return l.tun }

func (l *Lease) Activate(ctx context.Context, plan network.Plan) (returnErr error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.active != nil {
		return networkError("activate", "network lease is already active", nil)
	}
	link, err := netlink.LinkByName(l.cfg.Network.TunName)
	if err != nil {
		return networkError("activate", "find TUN device", err)
	}
	if err := verifyAlias(link, l.owner); err != nil {
		return networkError("activate", "verify TUN ownership", err)
	}
	if err := netlink.LinkSetMTU(link, l.cfg.Network.MTU); err != nil {
		return networkError("activate", "set TUN MTU", err)
	}
	address, err := netlink.ParseAddr(plan.VIPPrefix.String())
	if err != nil {
		return networkError("activate", "parse negotiated VIP", err)
	}
	if err := netlink.AddrAdd(link, address); err != nil {
		return networkError("activate", "assign negotiated VIP", err)
	}
	defer func() {
		if returnErr != nil {
			if cleanupErr := netlink.AddrDel(link, address); !ignorableDelete(cleanupErr) {
				returnErr = networkError("activate", "rollback was incomplete", errors.Join(returnErr, cleanupErr))
			}
		}
	}()
	if err := netlink.LinkSetUp(link); err != nil {
		return networkError("activate", "bring TUN up", err)
	}
	added := make([]netlink.Route, 0, len(plan.Routes))
	defer func() {
		if returnErr != nil {
			var cleanup []error
			for reverse := range len(added) {
				index := len(added) - 1 - reverse
				if err := netlink.RouteDel(&added[index]); !ignorableDelete(err) {
					cleanup = append(cleanup, err)
				}
			}
			if err := netlink.LinkSetDown(link); !ignorableDelete(err) {
				cleanup = append(cleanup, err)
			}
			if len(cleanup) > 0 {
				returnErr = networkError("activate", "rollback was incomplete", errors.Join(returnErr, errors.Join(cleanup...)))
			}
		}
	}()
	for _, prefix := range plan.Routes {
		route := activeRoute(l.cfg.Network.Table, link.Attrs().Index, plan.VIP, prefix)
		if err := netlink.RouteAdd(&route); err != nil {
			return networkError("activate", "install active route for "+prefix.String(), err)
		}
		added = append(added, route)
	}
	copy := plan
	copy.Routes = append([]netip.Prefix(nil), plan.Routes...)
	copy.Protected = append([]netip.Prefix(nil), plan.Protected...)
	l.active = &copy
	if err := l.writeJournal(); err != nil {
		l.active = nil
		return networkError("activate", "record active network state", err)
	}
	return nil
}

func (l *Lease) Suspend(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active == nil {
		return nil
	}
	plan := *l.active
	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	link, linkErr := netlink.LinkByName(l.cfg.Network.TunName)
	var cleanup []error
	if linkErr == nil {
		for _, prefix := range plan.Routes {
			route := activeRoute(l.cfg.Network.Table, link.Attrs().Index, plan.VIP, prefix)
			if err := netlink.RouteDel(&route); !ignorableDelete(err) {
				cleanup = append(cleanup, fmt.Errorf("delete active route %s: %w", prefix, err))
			}
		}
		address, err := netlink.ParseAddr(plan.VIPPrefix.String())
		if err == nil {
			if err := netlink.AddrDel(link, address); !ignorableDelete(err) {
				cleanup = append(cleanup, fmt.Errorf("delete VIP: %w", err))
			}
		}
		if err := netlink.LinkSetDown(link); err != nil && !ignorableDelete(err) {
			cleanup = append(cleanup, fmt.Errorf("set TUN down: %w", err))
		}
	} else if !ignorableDelete(linkErr) {
		cleanup = append(cleanup, linkErr)
	}
	if err := cleanupConntrack(plan); err != nil {
		cleanup = append(cleanup, err)
	}
	l.active = nil
	if err := l.writeJournal(); err != nil {
		cleanup = append(cleanup, err)
	}
	if len(cleanup) > 0 {
		return networkError("suspend", "network cleanup was incomplete", errors.Join(cleanup...))
	}
	return nil
}

func (l *Lease) Close() error {
	var cleanup []error
	l.mu.Lock()
	if l.active != nil {
		l.mu.Unlock()
		if err := l.Suspend(context.Background()); err != nil {
			cleanup = append(cleanup, err)
		}
		l.mu.Lock()
	}
	defer l.mu.Unlock()
	for index, prefix := range l.rules {
		rule := destinationRule(l.cfg.Network.Table, l.cfg.Network.RulePriority+index, prefix)
		if err := netlink.RuleDel(&rule); !ignorableDelete(err) {
			cleanup = append(cleanup, fmt.Errorf("delete rule %s: %w", prefix, err))
		}
	}
	for _, prefix := range l.guardRoutes {
		route := guardRoute(l.cfg.Network.Table, prefix)
		if err := netlink.RouteDel(&route); !ignorableDelete(err) {
			cleanup = append(cleanup, fmt.Errorf("delete guard route %s: %w", prefix, err))
		}
	}
	if link, err := netlink.LinkByName(l.cfg.Network.TunName); err == nil {
		if err := verifyAlias(link, l.owner); err != nil {
			cleanup = append(cleanup, err)
		} else if err := netlink.LinkDel(link); !ignorableDelete(err) {
			cleanup = append(cleanup, err)
		}
	} else if !ignorableDelete(err) {
		cleanup = append(cleanup, err)
	}
	if l.tun != nil {
		if err := l.tun.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			cleanup = append(cleanup, err)
		}
		l.tun = nil
	}
	if len(cleanup) == 0 {
		if err := os.Remove(l.journalPath); err != nil && !os.IsNotExist(err) {
			cleanup = append(cleanup, err)
		}
	}
	if len(cleanup) > 0 {
		return networkError("close", "network cleanup was incomplete", errors.Join(cleanup...))
	}
	return nil
}

func (l *Lease) writeJournal() error {
	state := journal{Owner: l.owner, TunName: l.cfg.Network.TunName, Table: l.cfg.Network.Table, RulePriority: l.cfg.Network.RulePriority}
	for _, prefix := range l.guardRoutes {
		state.GuardRoutes = append(state.GuardRoutes, prefix.String())
	}
	for _, prefix := range l.rules {
		state.Rules = append(state.Rules, prefix.String())
	}
	if l.active != nil {
		state.VIP = l.active.VIP.String()
		for _, prefix := range l.active.Routes {
			state.ActiveRoutes = append(state.ActiveRoutes, prefix.String())
		}
	}
	return writeJournal(l.journalPath, state)
}

func recoverJournal(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var state journal
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode network journal: %w", err)
	}
	if err := validateJournal(state); err != nil {
		return err
	}
	var cleanup []error
	var linkIndex int
	if link, err := netlink.LinkByName(state.TunName); err == nil {
		if err := verifyAlias(link, state.Owner); err != nil {
			return fmt.Errorf("refuse to recover unowned interface: %w", err)
		}
		linkIndex = link.Attrs().Index
		if err := netlink.LinkDel(link); !ignorableDelete(err) {
			cleanup = append(cleanup, err)
		}
	} else if !ignorableDelete(err) {
		cleanup = append(cleanup, err)
	}
	vip, _ := netip.ParseAddr(state.VIP)
	for _, raw := range state.ActiveRoutes {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			route := activeRoute(state.Table, linkIndex, vip, prefix)
			if err := netlink.RouteDel(&route); !ignorableDelete(err) {
				cleanup = append(cleanup, err)
			}
		}
	}
	for index, raw := range state.Rules {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			cleanup = append(cleanup, err)
			continue
		}
		rule := destinationRule(state.Table, state.RulePriority+index, prefix)
		if err := netlink.RuleDel(&rule); !ignorableDelete(err) {
			cleanup = append(cleanup, err)
		}
	}
	for _, raw := range state.GuardRoutes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			cleanup = append(cleanup, err)
			continue
		}
		route := guardRoute(state.Table, prefix)
		if err := netlink.RouteDel(&route); !ignorableDelete(err) {
			cleanup = append(cleanup, err)
		}
	}
	if len(cleanup) > 0 {
		return errors.Join(cleanup...)
	}
	return os.Remove(path)
}

func validateJournal(state journal) error {
	owner, err := hex.DecodeString(state.Owner)
	if err != nil || len(owner) != 16 || state.TunName == "" || len(state.TunName) > 15 || state.Table <= 0 || state.RulePriority <= 0 {
		return errors.New("network journal is incomplete")
	}
	if len(state.Rules) > len(state.GuardRoutes) {
		return errors.New("network journal records a rule without its guard route")
	}
	protected := make([]string, 0, len(state.GuardRoutes)+len(state.Rules))
	protected = append(protected, state.GuardRoutes...)
	protected = append(protected, state.Rules...)
	for _, raw := range protected {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() {
			return errors.New("network journal contains an invalid protected prefix")
		}
	}
	if len(state.ActiveRoutes) > 0 {
		vip, err := netip.ParseAddr(state.VIP)
		if err != nil || !vip.Is4() {
			return errors.New("network journal contains invalid active VIP state")
		}
	}
	for _, raw := range state.ActiveRoutes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() {
			return errors.New("network journal contains an invalid active route")
		}
	}
	return nil
}

func cleanupConntrack(plan network.Plan) error {
	filters := make([]netlink.CustomConntrackFilter, 0, len(plan.Routes)*2)
	vip := net.IP(plan.VIP.AsSlice())
	for _, prefix := range plan.Routes {
		networkValue := ipNet(prefix)
		local := &netlink.ConntrackFilter{}
		if err := local.AddIP(netlink.ConntrackOrigSrcIP, vip); err != nil {
			return err
		}
		if err := local.AddIPNet(netlink.ConntrackOrigDstIP, networkValue); err != nil {
			return err
		}
		filters = append(filters, local)
		forwarded := &netlink.ConntrackFilter{}
		if err := forwarded.AddIP(netlink.ConntrackReplyDstIP, vip); err != nil {
			return err
		}
		if err := forwarded.AddIPNet(netlink.ConntrackOrigDstIP, networkValue); err != nil {
			return err
		}
		filters = append(filters, forwarded)
	}
	if len(filters) == 0 {
		return nil
	}
	_, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, netlink.InetFamily(unix.AF_INET), filters...)
	if err != nil {
		return fmt.Errorf("delete conntrack entries limited to old VIP and routes: %w", err)
	}
	return nil
}

func guardRoute(table int, prefix netip.Prefix) netlink.Route {
	return netlink.Route{Dst: ipNet(prefix), Family: netlink.FAMILY_V4, Table: table, Type: unix.RTN_UNREACHABLE, Scope: unix.RT_SCOPE_UNIVERSE, Priority: 32760, Protocol: routeProtocol}
}
func activeRoute(table, linkIndex int, source netip.Addr, prefix netip.Prefix) netlink.Route {
	return netlink.Route{LinkIndex: linkIndex, Dst: ipNet(prefix), Src: net.IP(source.AsSlice()), Family: netlink.FAMILY_V4, Table: table, Type: unix.RTN_UNICAST, Scope: unix.RT_SCOPE_LINK, Priority: 10, Protocol: routeProtocol}
}
func destinationRule(table, priority int, prefix netip.Prefix) netlink.Rule {
	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V4
	rule.Table = table
	rule.Priority = priority
	rule.Dst = ipNet(prefix)
	rule.Protocol = uint8(routeProtocol)
	return *rule
}
func ipNet(prefix netip.Prefix) *net.IPNet {
	bits := prefix.Bits()
	return &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(bits, 32)}
}
func verifyAlias(link netlink.Link, owner string) error {
	if link.Attrs().Alias != "univpn:"+owner {
		return fmt.Errorf("interface %s is not owned by this transaction", link.Attrs().Name)
	}
	return nil
}
func randomOwner() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
func networkError(stage, message string, err error) error {
	if err == nil {
		return apperr.New(apperr.CodeNetwork, stage, apperr.RetryNever, message)
	}
	return apperr.Wrap(apperr.CodeNetwork, stage, apperr.RetryNever, message, err)
}
func ignorableDelete(err error) bool {
	return err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENODEV)
}

func writeJournal(path string, state journal) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".network-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
