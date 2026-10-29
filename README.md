# uni-next

Go/Linux client for the verified Huawei UniVPN `huawei-linux-base-v1` profile.

The project deliberately supports one evidence-backed path: TLS 1.2, username/password authentication, CNEM base control messages, and raw IPv4 over the SSL data tunnel. Unsupported authentication, GMTLS, outer UDP, IPsec, IPv6, and site-selection modes fail closed.

## Features

- Rootless single-user mode with an in-process IPv4/TCP/UDP stack; no TUN, policy routes, or `CAP_NET_ADMIN`.
- Local SOCKS5 TCP CONNECT/UDP ASSOCIATE and HTTP/1.1 forward/CONNECT proxies with active-route and target limits.
- Privileged Linux TUN split routing with an independent policy table and unreachable guards during reconnect.
- Pinned SHA-256 SPKI verification on every TLS connection; no insecure mode or silent cipher downgrade.
- Single lifecycle owner for authentication, CNEM, heartbeat, logout, cleanup, and bounded KICKOUT recovery.
- NetBird routing-peer compatibility without making the host a public exit node.
- Strict JSON configuration, runtime credentials, secret-free status, Nix package, and NixOS service module.

## Build

```console
nix build
./result/bin/uni-next version
```

For development:

```console
nix develop

go test ./...
go vet ./...
```

## Run

For a local proxy, run `proxy` as the logged-in user. It uses a userspace network stack and changes no host interfaces, routes, DNS, forwarding, or firewall state:

```console
uni-next proxy \
  --config ./proxy.json \
  --logout-user-id-file "$HOME/.config/uni-next/logout-user-id"
```

Both SOCKS5 and HTTP listeners default to loopback in this mode. See [`docs/proxy.example.json`](docs/proxy.example.json) and [`docs/configuration.md`](docs/configuration.md).

For host split routing or NetBird routing-peer service, use privileged `connect`. TUN creation, VIP assignment, and policy routing require `CAP_NET_ADMIN`, so production should run it under systemd as the dedicated `uni-next` user, never with setuid or file capabilities. The non-NixOS unit is [`deploy/uni-next.service`](deploy/uni-next.service); see [`docs/systemd.md`](docs/systemd.md). NixOS users use `services.uni-next`.

## Configuration

Start system-service configuration from [`docs/config.example.json`](docs/config.example.json), or rootless proxy configuration from [`docs/proxy.example.json`](docs/proxy.example.json). Both contain documentation-only addresses and certificate pins. See the complete [configuration and CLI reference](docs/configuration.md).

`connect` and `proxy` both accept an optional `--config`; explicitly supplied CLI flags override that file. For example:

```console
uni-next proxy \
  --config ./proxy.json \
  --server-host vpn.example \
  --route 10.20.0.0/16 \
  --http-listen 127.0.0.1:8181 \
  --logout-user-id-file "$HOME/.config/uni-next/logout-user-id"
uni-next check-config --config /etc/uni-next/config.json
uni-next status --run-dir "${XDG_RUNTIME_DIR:-$HOME/.cache}/uni-next" --json
```

VPN and proxy passwords must not be passed as command arguments or ordinary environment variables. Without `--vpn-password-file`, an interactive terminal receives a hidden password prompt. The current profile still requires an operator-confirmed gateway SPKI pin and a logout user ID supplied by a restricted file or systemd credential.

## NixOS

Add this repository as a flake input, import `inputs.uni-next.nixosModules.default`, and configure `services.uni-next`. See [`docs/nixos.md`](docs/nixos.md).

## NetBird

Use a NetBird **Network/routing peer** with explicit company CIDRs and masquerade enabled. Do not configure `0.0.0.0/0`; that is an exit node and is outside this design. See [`docs/netbird.md`](docs/netbird.md).

## Operational limits

- One UniVPN account/session per runtime directory. A second login can kick out the first.
- Existing TCP and UDP flows are closed when a reconnect changes the VIP.
- Rootless `proxy` uses the system resolver; it does not apply gateway-supplied DNS, so VPN-only DNS names may require local resolver configuration.
- Outer transport is TCP/TLS; TCP-over-TCP can perform poorly on lossy links.
- Non-loopback SOCKS in privileged `connect` mode is authenticated but not independently encrypted; use only on a trusted LAN or through NetBird. Rootless `proxy` rejects non-loopback listeners.
- Real gateway, real NetBird peer, and 24-hour acceptance testing require an operator-approved maintenance window. Offline tests do not prove those deployment properties.

Recovery and resource ownership are documented in [`docs/recovery.md`](docs/recovery.md). Security invariants are documented in [`docs/security.md`](docs/security.md).
