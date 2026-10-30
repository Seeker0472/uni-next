{
  lib,
  nixosSystem,
  pkgs,
}:

let
  package = pkgs.callPackage ../package.nix { };
  evaluated = nixosSystem {
    system = pkgs.stdenv.hostPlatform.system;
    modules = [
      ../module.nix
      {
        system.stateVersion = "25.11";
        services.uni-next = {
          enable = true;
          inherit package;
          openFirewall = true;
          netbirdService = "netbird-uni-next.service";
          credentials = {
            vpnPasswordFile = "/run/keys/uni-next-password";
            logoutUserIDFile = "/run/keys/uni-next-user-id";
          };
          settings = import ./settings.nix;
        };
      }
    ];
  };
  service = evaluated.config.systemd.services.uni-next;
  iptablesEvaluated = nixosSystem {
    system = pkgs.stdenv.hostPlatform.system;
    modules = [
      ../module.nix
      {
        system.stateVersion = "25.11";
        services.uni-next = {
          enable = true;
          inherit package;
          credentials = {
            vpnPasswordFile = "/run/keys/uni-next-password";
            logoutUserIDFile = "/run/keys/uni-next-user-id";
          };
          settings = (import ./settings.nix) // {
            socks.enabled = false;
          };
        };
      }
    ];
  };
  configFile = lib.last (lib.splitString " " service.serviceConfig.ExecStart);
  checkedConfig =
    assert evaluated.config.boot.kernel.sysctl."net.ipv4.ip_forward" == 1;
    assert lib.elem "CAP_NET_ADMIN" service.serviceConfig.CapabilityBoundingSet;
    assert lib.elem "vpn-password:/run/keys/uni-next-password" service.serviceConfig.LoadCredential;
    assert lib.elem 26 service.serviceConfig.RestartPreventExitStatus;
    assert lib.elem "netbird-uni-next.service" service.wants;
    assert lib.elem "netbird-uni-next.service" service.after;
    assert evaluated.config.networking.nftables.tables ? "uni-next-mss";
    assert evaluated.config.networking.nftables.enable;
    assert iptablesEvaluated.config.networking.firewall.backend == "iptables";
    assert lib.hasInfix "-t mangle -A FORWARD"
      iptablesEvaluated.config.networking.firewall.extraCommands;
    assert !iptablesEvaluated.config.networking.nftables.enable;
    configFile;
in
pkgs.runCommand "uni-next-module-check" { } ''
  ${package}/bin/uni-next check-config --config ${checkedConfig}
  touch "$out"
''
