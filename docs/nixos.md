# NixOS integration

## Flake input

```nix
{
  inputs.uni-next = {
    url = "path:/path/to/uni-next";
    inputs.nixpkgs.follows = "nixpkgs";
  };
}
```

Import `inputs.uni-next.nixosModules.default` in the target NixOS configuration. Credential option values are runtime path strings. Do not read secret contents with `builtins.readFile`, generate them with `pkgs.writeText`, or use literal secret values: those copy secrets into `/nix/store`.

A minimal split-tunnel service:

```nix
{ inputs, ... }: {
  imports = [ inputs.uni-next.nixosModules.default ];

  services.uni-next = {
    enable = true;
    credentials = {
      vpnPasswordFile = "/run/secrets/uni-next-password";
      logoutUserIDFile = "/run/secrets/uni-next-logout-user-id";
      socksPasswordFile = "/run/secrets/uni-next-socks-password";
    };
    settings = builtins.fromJSON (builtins.readFile ./uni-next.json);
  };
}
```

`uni-next.json` must contain no secrets. It may reside in the Nix store. Start from [`config.example.json`](config.example.json), replace its documentation-only values, and leave credential file fields absent: the module requires all credential paths under `services.uni-next.credentials` so `LoadCredential` cannot be shadowed. The module builds its package for the target host by default; set `package` only to override it. SPKI pins are public identifiers and may be stored declaratively after they have been verified through a trusted channel.

With sops-nix, point each credential option to a runtime secret path such as `config.sops.secrets.uni-next-password.path`. Set `restartUnits = [ "uni-next.service" ]` on each secret so rotation restarts the service. Declare the secrets in the host configuration; do not interpolate their plaintext into `settings`.

The service receives only `CAP_NET_ADMIN`, `/dev/net/tun`, bounded writable state directories, and required address families. Keep `runtime.state_dir` and `runtime.run_dir` at `/var/lib/uni-next` and `/run/uni-next`; the module checks these against its systemd directories. Exit codes 20–26 are excluded from systemd restart, including a transient network error when `reconnect.network.enabled=false`.

When `gateway.mode = "netbird"`, the module enables IPv4 forwarding and, when requested, nftables plus a narrow MSS clamp for the configured ingress interface, source ranges, destination ranges, and TUN. `openFirewall` likewise selects the NixOS nftables backend for its narrow input rules. The module does not change the global FORWARD policy or create NetBird management resources.

`openFirewall = true` adds source- and destination-limited TCP listener and UDP relay rules derived from SOCKS settings. Keep it false if the host firewall is managed elsewhere.

For non-NixOS hosts, use the hardened unit and runbook in [`systemd.md`](systemd.md).
