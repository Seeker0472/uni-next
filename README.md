# univpn

Go/Linux client for the verified Huawei UniVPN `huawei-linux-base-v1` profile.

The project deliberately supports one evidence-backed path: TLS 1.2, username/password authentication, CNEM base control messages, and raw IPv4 over the SSL data tunnel. Unsupported authentication, GMTLS, outer UDP, IPsec, IPv6, and site-selection modes fail closed.

## Features

- Linux TUN split routing with an independent policy table and unreachable guards during reconnect.
- Pinned SHA-256 SPKI verification on every TLS connection; no insecure mode or silent cipher downgrade.
- Single lifecycle owner for authentication, CNEM, heartbeat, logout, cleanup, and bounded KICKOUT recovery.
- SOCKS5 TCP CONNECT and UDP ASSOCIATE with source, authentication, active-route, target, and resource limits.
- NetBird routing-peer compatibility without making the host a public exit node.
- Strict JSON configuration, runtime credentials, secret-free status, Nix package, and NixOS service module.

## Build

```console
nix build
./result/bin/univpn version
```

For development:

```console
nix develop

go test ./...
go vet ./...
```

## Run

This is a privileged network service, not an ordinary user program. TUN creation, VIP assignment, and policy routing require `CAP_NET_ADMIN`, so run it under systemd as the dedicated `univpn` user, never with setuid or `setcap`. The non-NixOS unit is [`deploy/univpn.service`](deploy/univpn.service); see [`docs/systemd.md`](docs/systemd.md) for installation, credentials, status, and rotation. NixOS users use `services.univpn` instead.

## Configuration

Start from [`docs/config.example.json`](docs/config.example.json). It contains documentation-only addresses and no real credential or certificate. See the complete [configuration and CLI reference](docs/configuration.md) for defaults, constraints, credential precedence, and exit classes.

```console
univpn check-config --config /etc/univpn/config.json
sudo univpn connect --config /etc/univpn/config.json
univpn status --run-dir /run/univpn --json
```

`check-config` is offline. `connect` reads secrets from explicit files, an interactive terminal, or systemd credentials named `vpn-password`, `logout-user-id`, and `socks-password`. Passwords must not be passed as command arguments or ordinary environment variables.

The current profile requires an operator-confirmed gateway SPKI pin and logout user ID. It never learns or trusts a new certificate automatically.

## NixOS

Add this repository as a flake input, import `inputs.univpn.nixosModules.default`, and configure `services.univpn`. See [`docs/nixos.md`](docs/nixos.md).

## NetBird

Use a NetBird **Network/routing peer** with explicit company CIDRs and masquerade enabled. Do not configure `0.0.0.0/0`; that is an exit node and is outside this design. See [`docs/netbird.md`](docs/netbird.md).

## Operational limits

- One UniVPN account/session. A second login can kick out the first.
- Existing TCP and UDP flows are closed when a reconnect changes the VIP.
- Outer transport is TCP/TLS; TCP-over-TCP can perform poorly on lossy links.
- LAN SOCKS authentication and traffic are not independently encrypted; use only on a trusted LAN or through NetBird.
- Real gateway, real NetBird peer, and 24-hour acceptance testing require an operator-approved maintenance window. Offline tests do not prove those deployment properties.

Recovery and resource ownership are documented in [`docs/recovery.md`](docs/recovery.md). Security invariants are documented in [`docs/security.md`](docs/security.md).
