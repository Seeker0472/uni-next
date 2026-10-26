# Running as a system service (non-NixOS)

The client is a privileged network service. Creating a TUN interface, assigning the negotiated VIP, and installing policy routes/rules requires `CAP_NET_ADMIN`. It cannot do useful work as an ordinary login user.

Do **not** make the binary setuid or give it file capabilities with `setcap`. Either would let any local user who can execute it rewrite host routing and capture traffic. The supported model is a service manager that starts a dedicated system user with only `CAP_NET_ADMIN` and `/dev/net/tun`.

NixOS users should use `services.univpn` instead; it applies the same model automatically. This page covers other systemd distributions.

## Installed layout

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/univpn` | Binary. Adjust `ExecStart` if you install elsewhere. |
| `/etc/univpn/config.json` | Strict, non-secret runtime configuration. |
| `/etc/univpn/credentials/vpn-password` | Root-owned `0600` runtime VPN password. |
| `/etc/univpn/credentials/logout-user-id` | Root-owned `0600` logout user ID. |
| `/etc/univpn/credentials/socks-password` | Optional root-owned `0600` SOCKS password. |
| `/var/lib/univpn` | Network transaction journal and owned-resource recovery. |
| `/run/univpn` | Instance lock and read-only status snapshot. |

## Install

1. Build or install the binary:

   ```console
   nix build .#packages.x86_64-linux.univpn
   sudo install -Dm755 result/bin/univpn /usr/local/bin/univpn
   ```

2. Create the service identity:

   ```console
   sudo groupadd --system univpn
   sudo useradd --system --gid univpn --home-dir /var/lib/univpn \
     --shell /usr/sbin/nologin univpn
   ```

3. Install a non-secret configuration:

   ```console
   sudo install -Dm644 docs/config.example.json /etc/univpn/config.json
   sudoedit /etc/univpn/config.json
   ```

   Keep `runtime.state_dir` at `/var/lib/univpn` and `runtime.run_dir` at `/run/univpn`, or update the unit's `StateDirectory`/`RuntimeDirectory` consistently. Do not put passwords, tokens, or logout IDs in this file.

   Validate it without touching the network:

   ```console
   sudo univpn check-config --config /etc/univpn/config.json
   ```

4. Create root-owned credentials. Do not put them in shell arguments or environment variables.

   ```console
   sudo install -d -m 0700 /etc/univpn/credentials
   sudo install -m 0600 /dev/null /etc/univpn/credentials/vpn-password
   sudo install -m 0600 /dev/null /etc/univpn/credentials/logout-user-id
   sudoedit /etc/univpn/credentials/vpn-password
   sudoedit /etc/univpn/credentials/logout-user-id
   ```

   A single trailing newline is stripped. If SOCKS authentication is enabled, create `/etc/univpn/credentials/socks-password` the same way and uncomment the matching `LoadCredential` line in the unit.

5. Install and start the unit:

   ```console
   sudo install -Dm644 deploy/univpn.service /etc/systemd/system/univpn.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now univpn
   systemctl status univpn
   ```

   `LoadCredential` and `AmbientCapabilities` require a reasonably current systemd (247 or newer).

## Operating it

```console
sudo univpn status --run-dir /run/univpn --json
journalctl -u univpn -f
```

The status file is written `0640` under a `0750` directory owned by `univpn:univpn`. Read it as root, with `sudo -u univpn /usr/local/bin/univpn status --run-dir /run/univpn`, or add the administrator to the `univpn` group. The snapshot contains no passwords, tokens, session IDs, or packet data.

Configuration is read once at startup. After changing the JSON or rotating a credential file, restart:

```console
sudo systemctl restart univpn
```

Stopping with `systemctl stop univpn` sends SIGTERM, attempts logout within the configured timeout, and removes the TUN device, active routes, policy rules, guards, conntrack entries limited to the old VIP/routes, and the journal. `TimeoutStopSec=30s` bounds this.

Exit codes `20..25` are terminal and excluded from `Restart=on-failure`, so trust failures, unsupported responses, and exhausted KICKOUT policy do not form restart loops. Transient failures and unexpected exits restart after 10 seconds. After fixing a terminal condition:

```console
sudo systemctl reset-failed univpn
sudo systemctl start univpn
```

## Manual debugging

Stop the service first; the instance lock prevents two clients from sharing state.

```console
sudo systemctl stop univpn
sudo univpn connect --config /etc/univpn/config.json \
  --vpn-password-file /etc/univpn/credentials/vpn-password \
  --logout-user-id-file /etc/univpn/credentials/logout-user-id
```

This is a foreground debugging path only. It runs as root in this example; production should keep using the unit's dedicated user and capabilities.

## Rootless operation

There is no supported rootless mode. A user namespace can create a private TUN, but it has no host-wide effect and cannot provide the split-tunnel routing policy this client owns. If unprivileged users need access to internal destinations, enable the loopback or authenticated SOCKS listener and let them use that; the SOCKS server still runs inside the privileged service. NetBird access is governed by NetBird policy, not by running this client as an ordinary user.

## Limits

- `CAP_NET_ADMIN` is broad network control. The unit limits the capability set to it, but the service user is still privileged compared with an ordinary account.
- The unit never grants full root, `PrivateNetwork`, or a global firewall change.
- Do not disable reverse-path filtering globally or replace the FORWARD policy to make forwarding work. See [`netbird.md`](netbird.md) for the narrow forwarding/MSS model.
- Real gateway, real NetBird peer, and long-duration acceptance still require an operator-approved test.
