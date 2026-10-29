package session

import (
	"context"
	"net"
	"net/netip"
)

type kernelEgress struct {
	vip netip.Addr
}

func (e kernelEgress) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(e.vip.AsSlice())}}
	return dialer.DialContext(ctx, "tcp4", destination.String())
}

func (e kernelEgress) ListenUDP() (net.PacketConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(e.vip.AsSlice())})
}
