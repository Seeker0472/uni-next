package usernet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	genstate "github.com/seeker/uni-next/internal/generation"
	"github.com/seeker/uni-next/internal/network"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID tcpip.NICID = 1

var errInactive = errors.New("userspace network is inactive")

type Lease struct {
	mtu int
	mu  sync.RWMutex
	net *activeNetwork
}

type activeNetwork struct {
	stack    *stack.Stack
	endpoint *channel.Endpoint
	vip      netip.Addr
}

func New(mtu int) *Lease {
	return &Lease{mtu: mtu}
}

func (l *Lease) Device() network.PacketDevice { return l }

func (l *Lease) Activate(_ context.Context, plan network.Plan) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.net != nil {
		return errors.New("userspace network is already active")
	}

	networkStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        true,
	})
	endpoint := channel.New(1024, uint32(l.mtu), "")
	closeStack := true
	defer func() {
		if closeStack {
			endpoint.Close()
			networkStack.Close()
		}
	}()

	sack := tcpip.TCPSACKEnabled(true)
	if err := networkStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return fmt.Errorf("enable TCP SACK: %s", err)
	}
	if err := networkStack.CreateNIC(nicID, endpoint); err != nil {
		return fmt.Errorf("create userspace NIC: %s", err)
	}
	address := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(plan.VIP.AsSlice()),
			PrefixLen: plan.VIPPrefix.Bits(),
		},
	}
	if err := networkStack.AddProtocolAddress(nicID, address, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("assign userspace VPN address: %s", err)
	}
	routes := make([]tcpip.Route, 0, len(plan.Routes))
	for _, prefix := range plan.Routes {
		destination := tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(prefix.Addr().AsSlice()),
			PrefixLen: prefix.Bits(),
		}.Subnet()
		routes = append(routes, tcpip.Route{Destination: destination, NIC: nicID})
	}
	networkStack.SetRouteTable(routes)
	l.net = &activeNetwork{stack: networkStack, endpoint: endpoint, vip: plan.VIP}
	closeStack = false
	return nil
}

func (l *Lease) Suspend(context.Context) error {
	l.mu.Lock()
	active := l.net
	l.net = nil
	l.mu.Unlock()
	if active == nil {
		return nil
	}
	active.endpoint.Close()
	active.stack.RemoveNIC(nicID)
	active.stack.Close()
	return nil
}

func (l *Lease) Close() error { return l.Suspend(context.Background()) }

func (l *Lease) Name() string { return "userspace" }

func (l *Lease) ReadContext(ctx context.Context, destination []byte) (int, error) {
	active, err := l.active()
	if err != nil {
		return 0, err
	}
	packet := active.endpoint.ReadContext(ctx)
	if packet == nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return 0, errInactive
	}
	defer packet.DecRef()
	if packet.Size() > len(destination) {
		return 0, fmt.Errorf("userspace packet size %d exceeds buffer %d", packet.Size(), len(destination))
	}

	views, offset := packet.AsViewList()
	view := views.Front()
	for view != nil && offset >= view.Size() {
		offset -= view.Size()
		view = view.Next()
	}
	written := 0
	if view != nil {
		written += copy(destination, view.AsSlice()[offset:])
		for view = view.Next(); view != nil; view = view.Next() {
			written += copy(destination[written:], view.AsSlice())
		}
	}
	return written, nil
}

func (l *Lease) WriteContext(_ context.Context, packet []byte) (int, error) {
	active, err := l.active()
	if err != nil {
		return 0, err
	}
	if len(packet) == 0 || packet[0]>>4 != 4 {
		return 0, errors.New("userspace network accepts IPv4 packets only")
	}
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	defer packetBuffer.DecRef()
	active.endpoint.InjectInbound(ipv4.ProtocolNumber, packetBuffer)
	return len(packet), nil
}

func (l *Lease) Egress() (genstate.Egress, error) {
	return l.active()
}

func (l *Lease) active() (*activeNetwork, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.net == nil {
		return nil, errInactive
	}
	return l.net, nil
}

func (n *activeNetwork) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	address := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(destination.Addr().AsSlice()),
		Port: destination.Port(),
	}
	connection, err := gonet.DialContextTCP(ctx, n.stack, address, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return connection, nil
}

func (n *activeNetwork) ListenUDP() (net.PacketConn, error) {
	local := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(n.vip.AsSlice())}
	connection, err := gonet.DialUDP(n.stack, &local, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return connection, nil
}
