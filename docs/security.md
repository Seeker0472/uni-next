# Security invariants

- Every TLS connection is TLS 1.2 with one of the two verified ECDHE-RSA AES-GCM suites and an operator-confirmed SHA-256 SPKI pin.
- There is no user-configurable insecure mode, TOFU, legacy-cipher fallback, official-client fallback, or protocol auto-detection. The profile's certificate has no SAN, so Go's default CA/SAN verification is replaced by mandatory `VerifyConnection` checks for the pinned SPKI, validity period, server-auth usage, and RSA key strength; the TLS configuration separately fixes TLS 1.2 and the allowed cipher suites.
- Passwords and tokens never enter status snapshots or structured logs. Debug logging does not dump authentication requests or frames.
- JSON rejects duplicate and unknown keys. Unsupported profiles and unsafe routes fail before network login.
- Remote SOCKS listeners require an allowlist and independent RFC 1929 credentials. Targets must be inside both configured destinations and current negotiated routes.
- SOCKS UDP associations are bound to their TCP control connection, source IP/port, a finite relay port range, a finite remote set, and an idle timeout. Fragmented SOCKS UDP packets are rejected.
- The session gate closes all new proxy access before network suspension. Existing proxy sockets and UDP associations belong to one session generation and are not migrated.
- NetBird forwarding policy remains owned by NetBird. univpn owns only its TUN, exact policy routes/rules, journal, and narrowly matched conntrack deletion.
- Runtime secrets should be supplied by systemd credentials, sops-nix, agenix, or equally restricted files. Ordinary environment variables and command arguments are unsupported.
- The Go process uses `CAP_NET_ADMIN`; this is a meaningful privilege boundary, not a sandbox equivalent to a separate helper process.
