# Configuration and CLI reference

The runtime file is strict JSON, limited to 1 MiB. Unknown keys, duplicate keys, trailing JSON values, unsupported modes, and unsafe route relationships are errors. Omitted known fields receive the defaults below; configuration is read once at process start.

Use [`config.example.json`](config.example.json) as the starting point and validate it without network or TUN access:

```console
univpn check-config --config /etc/univpn/config.json
```

## Required profile and trust settings

| Key | Constraint / default |
| --- | --- |
| `schema_version` | Must be `1`. |
| `protocol.profile` | Must be `huawei-linux-base-v1`. |
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
| `network.tun_name` | `univpn0`; Linux interface name, at most 15 bytes. |
| `network.mtu` | `1300`; accepted range `576..1300`. |
| `network.allowed_routes` | Required IPv4 CIDRs. Negotiated routes are intersected with this set; the same set receives reconnect guards. Default routes, multicast, loopback, and unspecified ranges are rejected. |
| `network.table` | `20000`; dedicated policy-routing table. |
| `network.rule_priority` | `100`; one destination rule is allocated per protected prefix and must remain below priority `32766`. |
| `timeouts.connect`, `tls`, `auth`, `control_step`, `write`, `logout` | `10s`, `10s`, `20s`, `10s`, `10s`, `5s`; all positive Go durations. |
| `heartbeat.interval`, `heartbeat.timeout` | `10s`, `35s`; timeout must exceed interval. |
| `reconnect.network.enabled` | `true`; enables retry only for classified transient network failures. |
| `reconnect.initial`, `maximum`, `reset_after` | `5s`, `1m`, `5m`; bounded exponential delay and healthy-generation reset threshold. |
| `reconnect.kickout.mode` | `bounded`; `stop`, `bounded`, or `always`. |
| `reconnect.kickout.window`, `max_retries` | `10m`, `3`; bounded retry budget for gateway type-8 KICKOUT. |
| `runtime.state_dir`, `run_dir` | `/var/lib/univpn`, `/run/univpn`; both must be absolute. |
| `logging.level` | `info`; `debug`, `info`, `warn`, or `error`. |
| `logging.format` | `text`; `text` or `json`. |

Changing the dedicated table or rule-priority range requires checking for conflicts with the host and NetBird before deployment.

## SOCKS5

| Key | Constraint / default |
| --- | --- |
| `socks.enabled` | `false`. |
| `socks.listeners` | `127.0.0.1:1080`; explicit IPv4 address and port, never an unspecified address. Missing non-loopback addresses are retried for 30 seconds, then fail. |
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

## NetBird gateway mode

`gateway.mode` is `off` by default. `netbird` requires `ingress_interface`, non-empty bounded `source_cidrs`, and non-empty `export_routes`. Exported routes must be subsets of `network.allowed_routes`. `clamp_tcp_mss` defaults to true and is implemented by the NixOS module; the Go process does not mutate nftables or global forwarding state.

## Commands and exit classes

```console
univpn connect --config /etc/univpn/config.json
univpn check-config --config /etc/univpn/config.json
univpn status --run-dir /run/univpn --json
univpn version
```

`connect` stays in the foreground and handles SIGINT/SIGTERM. `status` rejects a stale PID and never contains credentials, session IDs, tokens, or packet data.

| Exit | Meaning |
| ---: | --- |
| `0` | Successful command or clean informational result. |
| `20` | Configuration or local preflight failure. |
| `21` | Reserved for a gateway-confirmed authentication rejection. The current profile never fabricates one from an unrecognized response. |
| `22` | Unsupported platform, profile, or protocol response. |
| `23` | TLS pin/trust failure. |
| `24` | KICKOUT policy stopped the session. |
| `25` | TUN, policy-routing, ownership, or cleanup failure. |

Unclassified or transient network errors exit `1`, allowing the NixOS unit's `Restart=on-failure` policy to retry them. Exit classes `20..25` are terminal for systemd.
