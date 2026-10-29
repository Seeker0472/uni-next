# NetBird routing-peer integration

The uni-next host must run a NetBird peer. Running only the NetBird management server does not create a data-plane routing peer.

1. Create a NetBird Network with one resource for each intended UniVPN CIDR.
2. Assign the uni-next host peer as the routing peer.
3. Keep masquerade enabled. The company network normally has no return route for NetBird overlay addresses.
4. Grant access from explicit user/device groups to those resources.
5. Do not publish `0.0.0.0/0`; this client shares only UniVPN internal routes, not the host's public internet connection.
6. To expose SOCKS on the host's NetBird address, add a separate peer-to-peer policy for the TCP listener and configured UDP relay range. Routed resources use FORWARD policy; the host SOCKS service uses INPUT policy.
7. Configure `gateway.mode = "netbird"`, the real NetBird interface, the account's actual overlay CIDR, and the exact exported CIDRs.

The program installs unreachable policy routes before login. During reconnect, local and forwarded packets for configured protected CIDRs terminate there instead of falling through to the physical default route. NetBird owns its forwarding authorization and masquerade rules; uni-next does not flush or replace them.

## Non-NixOS host integration

The host administrator must enable IPv4 forwarding, authorize only the intended NetBird interface/source/destination path in the existing FORWARD policy, and own the MSS rule. Do not change the global FORWARD policy to ACCEPT and do not disable reverse-path filtering globally.

Equivalent nftables MSS clamping, with every placeholder replaced by the deployed values:

```nft
table inet uni-next-mss {
  chain forward {
    type filter hook forward priority mangle; policy accept;
    iifname "wt0" oifname "uni-next0" ip saddr { 100.64.0.0/10 } ip daddr { 10.19.20.0/24 } tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu
  }
}
```

This table is declarative host configuration, not a resource created by the Go process. Scope it to the real ingress, TUN, NetBird source range, and exported UniVPN destinations. MSS clamp covers TCP SYN only; validate UDP PMTU, ICMP fragmentation-needed, DF/non-DF traffic, and legal IPv4 fragments separately.

Validation must use another real peer:

- ICMP, TCP, and UDP to an allowed internal target succeed.
- A peer outside the authorized group cannot reach the resource.
- The client peer's ordinary public egress IP remains unchanged.
- Traffic arriving at the internal resource has the current UniVPN VIP after NetBird and kernel NAT.
- During a forced UniVPN disconnect, packet capture on the physical uplink shows no protected-destination traffic.
- TCP MSS, IPv4 fragmentation, and UDP near the 1300-byte tunnel MTU behave correctly.

A management-dashboard `Connected` state is not sufficient evidence.
