# Configuration and CLI reference

Configuration is strict JSON, limited to 1 MiB. Unknown keys, duplicate keys, trailing JSON values, unsupported modes, and unsafe route relationships are errors. Omitted known fields receive command defaults, and configuration is read once at process start. `connect` and `proxy` may run without a file when all required values are supplied by CLI.

Use [`config.example.json`](config.example.json) for privileged system mode or [`proxy.example.json`](proxy.example.json) for rootless proxy mode. Validate a complete file without network or TUN access:

```console
uni-next check-config --config /etc/uni-next/config.json
```

## Required profile and trust settings

| Key | Constraint / default |
| --- | --- |
| `schema_version` | Must be `1`. |
| `protocol.profile` | Must be `cnem-base-v1`. |
| `server.host` | Required gateway DNS name or IP; CR/LF rejected. |
| `server.port` | `9443`; must be non-zero. |
| `auth.username` | Required; CR/LF rejected. |
| `auth.mac` | Required six-byte MAC used by the verified profile. |
| `auth.password_file` | Optional explicit runtime path. If absent, systemd credential `vpn-password`, then an interactive terminal, is used. |
| `auth.logout_user_id_file` | Required runtime value for logout. If absent, systemd credential `logout-user-id` is used. |
| `tls.spki_sha256` | One or more base64 or hexadecimal SHA-256 SPKI pins. Mutually exclusive with `spki_pin_file`. |
| `tls.spki_pin_file` | Runtime file containing one pin per non-empty line. Mutually exclusive with inline pins. |
| `tls.cipher_suites` | The default and only supported values are `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`. |

A pin is a public identifier, but it must be confirmed over a trusted administrative channel. Pin mismatch is terminal; the client never learns a replacement automatically.

## Tunnel and lifecycle

| Key | Constraint / default |
| --- | --- |
| `network.tun_name` | `uni-next0`; Linux interface name, at most 15 bytes. Used by `connect`; ignored by rootless `proxy`. |
| `network.mtu` | `1300`; accepted range `576..1300`; used by both TUN and userspace stacks. |
| `network.allowed_routes` | Required IPv4 CIDRs. Negotiated routes are intersected with this set. `connect` also installs reconnect guards; `proxy` uses the result only for userspace target and route policy. Default routes, multicast, loopback, and unspecified ranges are rejected. |
| `network.table` | `20000`; dedicated policy-routing table used only by `connect`. |
| `network.rule_priority` | `100`; one destination rule is allocated per protected prefix by `connect` and must remain below priority `32766`. |
| `timeouts.connect`, `tls`, `auth`, `control_step`, `write`, `logout` | `10s`, `10s`, `20s`, `10s`, `10s`, `5s`; all positive Go durations. |
| `heartbeat.interval`, `heartbeat.timeout` | `10s`, `35s`; timeout must exceed interval. |
| `reconnect.network.enabled` | `true`; enables retry only for classified transient network failures. |
| `reconnect.initial`, `maximum`, `reset_after` | `5s`, `1m`, `5m`; bounded exponential delay and healthy-generation reset threshold. |
| `reconnect.kickout.mode` | `bounded`; `stop`, `bounded`, or `always`. |
| `reconnect.kickout.window`, `max_retries` | `10m`, `3`; bounded retry budget for gateway type-8 KICKOUT. |
| `runtime.state_dir`, `run_dir` | `/var/lib/uni-next`, `/run/uni-next` for `connect`. CLI-only `proxy` defaults to the per-user config directory and `$XDG_RUNTIME_DIR/uni-next`, falling back to the user cache directory when `XDG_RUNTIME_DIR` is absent. Both must be absolute. |
| `logging.level` | `info`; `debug`, `info`, `warn`, or `error`. |
| `logging.format` | `text`; `text` or `json`. |

Changing the dedicated table or rule-priority range requires checking for conflicts with the host and NetBird before deployment.

## Rootless proxy mode

`uni-next proxy` uses an in-process IPv4/TCP/UDP stack. It does not open `/dev/net/tun`, require `CAP_NET_ADMIN`, or mutate host routes, DNS, forwarding, nftables, or conntrack. `gateway.mode` must be `off`, at least one proxy protocol must be enabled, and all listeners must be loopback addresses.

The userspace stack and every accepted proxy connection belong to one VPN generation. Reconnect closes existing TCP connections and UDP associations before a new VIP becomes available. Hostname lookup deliberately uses the system resolver; every returned IPv4 address must satisfy both configured destinations and the active negotiated routes.

## SOCKS5

| Key | Constraint / default |
| --- | --- |
| `socks.enabled` | `false` for `connect`, `true` for CLI-only `proxy`. |
| `socks.listeners` | `127.0.0.1:1080`; explicit IPv4 address and port, never an unspecified address. Rootless `proxy` accepts loopback only. Missing non-loopback addresses in `connect` are retried for 30 seconds, then fail. |
| `socks.allow_sources` | IPv4 source CIDRs. Non-loopback listeners require a non-empty list; `/0` and multicast sources are rejected. |
| `socks.auth.username` | Required for a non-loopback listener; at most 255 bytes. |
| `socks.auth.password_file` | Runtime file, or systemd credential `socks-password`; independent of the VPN password. |
| `socks.allow_loopback_no_auth` | `false`; permits RFC 1928 no-auth only for loopback clients. It never weakens a remote listener. |
| `socks.allowed_destinations` | Defaults to `network.allowed_routes`; every entry must be a subset. A target must also be inside the current negotiated routes. |
| `max_tcp_connections`, `max_per_source` | `512`, `64`; positive global and per-source limits. |
| `handshake_timeout`, `dial_timeout`, `tcp_idle_timeout` | `10s`, `10s`, `0s`; zero TCP idle timeout disables it. |
| `udp.enabled` | `true` when SOCKS is enabled by defaults. |
| `udp.port_range.from`, `to` | `20000..20255`; finite relay ports for firewall policy. |
| `udp.max_associations`, `max_remotes_per_association`, `idle_timeout` | `128`, `64`, `2m`; positive bounds. Associations must fit in the port range. |

Remote SOCKS is authenticated but not encrypted. Use it only on a trusted network or over NetBird.

## HTTP proxy

The HTTP listener supports HTTP/1.1 absolute-form forwarding and HTTPS `CONNECT`. It is intentionally loopback-only and has no proxy-authentication surface.

| Key | Constraint / default |
| --- | --- |
| `http.enabled` | `false` for `connect`, `true` for CLI-only `proxy`. |
| `http.listeners` | `127.0.0.1:8080`; explicit IPv4 loopback addresses only. |
| `http.allowed_destinations` | Defaults to `network.allowed_routes`; every entry must be a subset and each resolved target must also be inside current negotiated routes. |
| `http.max_connections`, `max_per_source` | `512`, `64`; positive global and per-source TCP connection limits. |
| `http.read_header_timeout`, `dial_timeout`, `idle_timeout` | `10s`, `10s`, `2m`; header and dial timeouts must be positive; zero idle timeout disables it. |

Hop-by-hop and proxy-authorization headers are removed. HTTP/2 proxying, WebSocket upgrade forwarding, transparent interception, and non-loopback HTTP listeners are unsupported.

## NetBird gateway mode

`gateway.mode` is `off` by default. `netbird` requires `ingress_interface`, non-empty bounded `source_cidrs`, and non-empty `export_routes`. Exported routes must be subsets of `network.allowed_routes`. `clamp_tcp_mss` defaults to true and is implemented by the NixOS module; the Go process does not mutate nftables or global forwarding state.

## Commands and CLI overrides

```console
uni-next connect [--config /etc/uni-next/config.json] [overrides]
uni-next proxy [--config ./proxy.json] [overrides]
uni-next check-config --config /etc/uni-next/config.json
uni-next status --run-dir /run/uni-next --json
uni-next version
```

`connect` and `proxy` use the same precedence: command defaults, then the optional strict JSON file, then explicitly present CLI flags. Validation runs after all three layers, so required values may come entirely from CLI. Scalar flags use their last occurrence. If any repeatable list flag is present, its values replace the complete JSON list rather than append to it.

| CLI flag | Final configuration field |
| --- | --- |
| `--server-host`, `--server-port` | `server.host`, `server.port` |
| `--username`, `--mac` | `auth.username`, `auth.mac` |
| repeatable `--spki-sha256` | replaces `tls.spki_sha256` and clears `tls.spki_pin_file` |
| `--spki-pin-file` | replaces `tls.spki_pin_file` and clears inline pins |
| repeatable `--route` | replaces `network.allowed_routes` |
| `--socks=true|false`, repeatable `--socks-listen`, `--socks-loopback-no-auth=true|false` | SOCKS enablement, listeners, and loopback authentication |
| `--http=true|false`, repeatable `--http-listen` | HTTP enablement and listeners |
| `--run-dir`, `--state-dir` | runtime directories |
| `--log-level`, `--log-format` | logging settings |

`--vpn-password-file`, `--logout-user-id-file`, and `--socks-password-file` override only credential sources. Password values are never accepted in argv or ordinary environment variables. Without a VPN password file, an interactive terminal receives a hidden prompt. The logout user ID remains file/systemd-credential only.

Both connection commands stay in the foreground and handle SIGINT/SIGTERM. `status` rejects a stale PID, reports system/proxy mode plus SOCKS/HTTP readiness, and never contains credentials, session IDs, tokens, or packet data.

| Exit | Meaning |
| ---: | --- |
| `0` | Successful command or clean informational result. |
| `20` | Configuration or local preflight failure. |
| `21` | Reserved for a gateway-confirmed authentication rejection. The current profile never fabricates one from an unrecognized response. |
| `22` | Unsupported platform, profile, or protocol response. |
| `23` | TLS pin/trust failure. |
| `24` | KICKOUT policy stopped the session. |
| `25` | TUN, userspace network stack, policy-routing, ownership, or cleanup failure. |

Unclassified or transient network errors exit `1`, allowing the NixOS unit's `Restart=on-failure` policy to retry them. Exit classes `20..25` are terminal for systemd.
