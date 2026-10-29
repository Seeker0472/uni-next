# Running as a system service (non-NixOS)

The client is a privileged network service. Creating a TUN interface, assigning the negotiated VIP, and installing policy routes/rules requires `CAP_NET_ADMIN`. It cannot do useful work as an ordinary login user.

Do **not** make the binary setuid or give it file capabilities with `setcap`. Either would let any local user who can execute it rewrite host routing and capture traffic. The supported model is a service manager that starts a dedicated system user with only `CAP_NET_ADMIN` and `/dev/net/tun`.

NixOS users should use `services.uni-next` instead; it applies the same model automatically. This page covers other systemd distributions.

## Installed layout

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/uni-next` | Binary. Adjust `ExecStart` if you install elsewhere. |
| `/etc/uni-next/config.json` | Strict, non-secret runtime configuration. |
| `/etc/uni-next/credentials/vpn-password` | Root-owned `0600` runtime VPN password. |
| `/etc/uni-next/credentials/logout-user-id` | Root-owned `0600` logout user ID. |
| `/etc/uni-next/credentials/socks-password` | Optional root-owned `0600` SOCKS password. |
| `/var/lib/uni-next` | Network transaction journal and owned-resource recovery. |
| `/run/uni-next` | Instance lock and read-only status snapshot. |

## Install

1. Build or install the binary:

   ```console
   nix build .#packages.x86_64-linux.uni-next
   sudo install -Dm755 result/bin/uni-next /usr/local/bin/uni-next
   ```

2. Create the service identity:

   ```console
   sudo groupadd --system uni-next
   sudo useradd --system --gid uni-next --home-dir /var/lib/uni-next \
     --shell /usr/sbin/nologin uni-next
   ```

3. Install a non-secret configuration:

   ```console
   sudo install -Dm644 docs/config.example.json /etc/uni-next/config.json
   sudoedit /etc/uni-next/config.json
   ```

   Keep `runtime.state_dir` at `/var/lib/uni-next` and `runtime.run_dir` at `/run/uni-next`, or update the unit's `StateDirectory`/`RuntimeDirectory` consistently. Do not put passwords, tokens, or logout IDs in this file.

   Validate it without touching the network:

   ```console
   sudo uni-next check-config --config /etc/uni-next/config.json
   ```

4. Create root-owned credentials. Do not put them in shell arguments or environment variables.

   ```console
   sudo install -d -m 0700 /etc/uni-next/credentials
   sudo install -m 0600 /dev/null /etc/uni-next/credentials/vpn-password
   sudo install -m 0600 /dev/null /etc/uni-next/credentials/logout-user-id
   sudoedit /etc/uni-next/credentials/vpn-password
   sudoedit /etc/uni-next/credentials/logout-user-id
   ```

   A single trailing newline is stripped. If SOCKS authentication is enabled, create `/etc/uni-next/credentials/socks-password` the same way and uncomment the matching `LoadCredential` line in the unit.

5. Install and start the unit:

   ```console
   sudo install -Dm644 deploy/uni-next.service /etc/systemd/system/uni-next.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now uni-next
   systemctl status uni-next
   ```

   `LoadCredential` and `AmbientCapabilities` require a reasonably current systemd (247 or newer).

## Operating it

```console
sudo uni-next status --run-dir /run/uni-next --json
journalctl -u uni-next -f
```

The status file is written `0640` under a `0750` directory owned by `uni-next:uni-next`. Read it as root, with `sudo -u uni-next /usr/local/bin/uni-next status --run-dir /run/uni-next`, or add the administrator to the `uni-next` group. The snapshot contains no passwords, tokens, session IDs, or packet data.

Configuration is read once at startup. After changing the JSON or rotating a credential file, restart:

```console
sudo systemctl restart uni-next
```

Stopping with `systemctl stop uni-next` sends SIGTERM, attempts logout within the configured timeout, and removes the TUN device, active routes, policy rules, guards, conntrack entries limited to the old VIP/routes, and the journal. `TimeoutStopSec=30s` bounds this.

Exit codes `20..25` are terminal and excluded from `Restart=on-failure`, so trust failures, unsupported responses, and exhausted KICKOUT policy do not form restart loops. Transient failures and unexpected exits restart after 10 seconds. After fixing a terminal condition:

```console
sudo systemctl reset-failed uni-next
sudo systemctl start uni-next
```

## Manual debugging

Stop the service first; the instance lock prevents two clients from sharing state.

```console
sudo systemctl stop uni-next
sudo uni-next connect --config /etc/uni-next/config.json \
  --vpn-password-file /etc/uni-next/credentials/vpn-password \
  --logout-user-id-file /etc/uni-next/credentials/logout-user-id
```

This is a foreground debugging path only. It runs as root in this example; production should keep using the unit's dedicated user and capabilities.

## Rootless operation

There is no supported rootless mode. A user namespace can create a private TUN, but it has no host-wide effect and cannot provide the split-tunnel routing policy this client owns. If unprivileged users need access to internal destinations, enable the loopback or authenticated SOCKS listener and let them use that; the SOCKS server still runs inside the privileged service. NetBird access is governed by NetBird policy, not by running this client as an ordinary user.

## Limits

- `CAP_NET_ADMIN` is broad network control. The unit limits the capability set to it, but the service user is still privileged compared with an ordinary account.
- The unit never grants full root, `PrivateNetwork`, or a global firewall change.
- Do not disable reverse-path filtering globally or replace the FORWARD policy to make forwarding work. See [`netbird.md`](netbird.md) for the narrow forwarding/MSS model.
- Real gateway, real NetBird peer, and long-duration acceptance still require an operator-approved test.
