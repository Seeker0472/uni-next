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

Import `inputs.uni-next.nixosModules.default` in the target NixOS configuration. Credential option values are runtime path strings. Do not use `builtins.readFile`, `pkgs.writeText`, or literal secret values: those copy secrets into `/nix/store`.

A minimal split-tunnel service:

```nix
{ inputs, pkgs, ... }: {
  imports = [ inputs.uni-next.nixosModules.default ];

  services.uni-next = {
    enable = true;
    package = inputs.uni-next.packages.${pkgs.stdenv.hostPlatform.system}.default;
    credentials = {
      vpnPasswordFile = "/run/secrets/uni-next-password";
      logoutUserIDFile = "/run/secrets/uni-next-logout-user-id";
      socksPasswordFile = "/run/secrets/uni-next-socks-password";
    };
    settings = builtins.fromJSON (builtins.readFile ./uni-next.json);
  };
}
```

`uni-next.json` must contain no secrets. It may reside in the Nix store. SPKI pins are public identifiers and may be stored declaratively after they have been verified through a trusted channel.

The service receives only `CAP_NET_ADMIN`, `/dev/net/tun`, bounded writable state directories, and required address families. Exit codes 20–25 are excluded from systemd restart so certificate changes, unsupported protocol responses, resource conflicts, or exhausted KICKOUT policy do not form restart loops.

When `gateway.mode = "netbird"`, the module enables IPv4 forwarding and, when requested, nftables plus a narrow MSS clamp for the configured ingress interface, source ranges, destination ranges, and TUN. `openFirewall` likewise selects the NixOS nftables backend for its narrow input rules. The module does not change the global FORWARD policy or create NetBird management resources.

`openFirewall = true` adds source- and destination-limited TCP listener and UDP relay rules derived from SOCKS settings. Keep it false if the host firewall is managed elsewhere.

For non-NixOS hosts, use the hardened unit and runbook in [`systemd.md`](systemd.md).
