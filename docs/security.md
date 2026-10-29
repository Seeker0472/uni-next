# Security invariants

- Every TLS connection is TLS 1.2 with one of the two verified ECDHE-RSA AES-GCM suites and an operator-confirmed SHA-256 SPKI pin.
- There is no user-configurable insecure mode, TOFU, legacy-cipher fallback, official-client fallback, or protocol auto-detection. The profile's certificate has no SAN, so Go's default CA/SAN verification is replaced by mandatory `VerifyConnection` checks for the pinned SPKI, validity period, server-auth usage, and RSA key strength; the TLS configuration separately fixes TLS 1.2 and the allowed cipher suites.
- Passwords and tokens never enter status snapshots or structured logs. Debug logging does not dump authentication requests or frames.
- JSON rejects duplicate and unknown keys. Unsupported profiles and unsafe routes fail before network login.
- SOCKS and HTTP targets must be inside both configured destinations and current negotiated routes. DNS resolution fails closed if any returned IPv4 address falls outside policy.
- Remote SOCKS listeners require an allowlist and independent RFC 1929 credentials. Rootless `proxy` permits only loopback SOCKS and HTTP listeners; HTTP proxy authentication and remote exposure are intentionally absent.
- SOCKS UDP associations are bound to their TCP control connection, source IP/port, one session generation, a finite relay port range, a finite remote set, and an idle timeout. Fragmented SOCKS UDP packets are rejected.
- HTTP accepts only HTTP/1.1 absolute-form `http` requests and `CONNECT`; it strips hop-by-hop and proxy-authorization headers and applies bounded headers, connections, targets, and timeouts.
- The session gate closes all new proxy access before network suspension. Existing SOCKS TCP/UDP, HTTP response, and CONNECT flows belong to one session generation and are not migrated.
- Rootless `proxy` carries raw IPv4 between the TLS tunnel and an in-process TCP/IP stack. It never opens TUN or mutates host interfaces, routes, DNS, forwarding, firewall, or conntrack state.
- Privileged `connect` keeps NetBird forwarding policy owned by NetBird. uni-next owns only its TUN, exact policy routes/rules, journal, and narrowly matched conntrack deletion.
- Runtime secrets should be supplied by systemd credentials, restricted files, or an interactive terminal. Password values in ordinary environment variables and command arguments remain unsupported.
- `connect` uses `CAP_NET_ADMIN` under a dedicated service user; there is no setuid/setcap binary or supported root-running client. `proxy` runs as the invoking user without capabilities and stores its lock/status under the per-user runtime directory by default.
