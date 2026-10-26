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
        services.univpn = {
          enable = true;
          inherit package;
          openFirewall = true;
          credentials = {
            vpnPasswordFile = "/run/keys/univpn-password";
            logoutUserIDFile = "/run/keys/univpn-user-id";
          };
          settings = import ./settings.nix;
        };
      }
    ];
  };
  service = evaluated.config.systemd.services.univpn;
  configFile = lib.last (lib.splitString " " service.serviceConfig.ExecStart);
  checkedConfig =
    assert evaluated.config.boot.kernel.sysctl."net.ipv4.ip_forward" == 1;
    assert lib.elem "CAP_NET_ADMIN" service.serviceConfig.CapabilityBoundingSet;
    assert lib.elem "vpn-password:/run/keys/univpn-password" service.serviceConfig.LoadCredential;
    assert evaluated.config.networking.nftables.tables ? "univpn-mss";
    assert evaluated.config.networking.nftables.enable;
    configFile;
in
pkgs.runCommand "univpn-module-check" { } ''
  ${package}/bin/univpn check-config --config ${checkedConfig}
  touch "$out"
''
