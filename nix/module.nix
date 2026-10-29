{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.services.uni-next;
  json = pkgs.formats.json { };
  configFile =
    if hasInlineSecret then
      throw "services.uni-next.settings contains an inline secret"
    else
      json.generate "uni-next.json" cfg.settings;

  get = path: fallback: lib.attrByPath path fallback cfg.settings;
  socksEnabled = get [ "socks" "enabled" ] false;
  listeners = get [ "socks" "listeners" ] [ ];
  sources = get [ "socks" "allow_sources" ] [ ];
  udpEnabled = get [ "socks" "udp" "enabled" ] false;
  udpFrom = get [ "socks" "udp" "port_range" "from" ] 0;
  udpTo = get [ "socks" "udp" "port_range" "to" ] 0;
  gatewayMode = get [ "gateway" "mode" ] "off";
  gatewayInterface = get [ "gateway" "ingress_interface" ] "";
  gatewaySources = get [ "gateway" "source_cidrs" ] [ ];
  gatewayRoutes = get [ "gateway" "export_routes" ] [ ];
  tunName = get [ "network" "tun_name" ] "uni-next0";
  clampMSS = get [ "gateway" "clamp_tcp_mss" ] true;

  parseListener =
    value:
    let
      parts = lib.splitString ":" value;
    in
    {
      address = builtins.elemAt parts 0;
      port = builtins.fromJSON (builtins.elemAt parts 1);
    };
  parsedListeners = map parseListener listeners;
  hasRemoteListener = lib.any (value: !(lib.hasPrefix "127." value)) listeners;
  set = values: "{ ${lib.concatStringsSep ", " values} }";

  tcpFirewallRules = lib.concatMapStringsSep "\n" (
    listener:
    "ip saddr ${set sources} ip daddr ${listener.address} tcp dport ${toString listener.port} accept comment \"uni-next SOCKS TCP\""
  ) parsedListeners;
  udpFirewallRules = lib.concatMapStringsSep "\n" (
    listener:
    "ip saddr ${set sources} ip daddr ${listener.address} udp dport ${toString udpFrom}-${toString udpTo} accept comment \"uni-next SOCKS UDP\""
  ) parsedListeners;

  credentials = lib.filter (value: value != null) [
    (
      if cfg.credentials.vpnPasswordFile == null then
        null
      else
        "vpn-password:${cfg.credentials.vpnPasswordFile}"
    )
    (
      if cfg.credentials.logoutUserIDFile == null then
        null
      else
        "logout-user-id:${cfg.credentials.logoutUserIDFile}"
    )
    (
      if cfg.credentials.socksPasswordFile == null then
        null
      else
        "socks-password:${cfg.credentials.socksPasswordFile}"
    )
  ];
  credentialPaths = lib.filter (value: value != null) [
    cfg.credentials.vpnPasswordFile
    cfg.credentials.logoutUserIDFile
    cfg.credentials.socksPasswordFile
  ];
  hasInlineSecret =
    lib.hasAttrByPath [ "auth" "password" ] cfg.settings
    || lib.hasAttrByPath [ "auth" "logout_user_id" ] cfg.settings
    || lib.hasAttrByPath [ "socks" "auth" "password" ] cfg.settings;
in
{
  options.services.uni-next = {
    enable = mkEnableOption "uni-next VPN client";
    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      description = "uni-next package to execute.";
    };
    settings = mkOption {
      type = json.type;
      default = { };
      description = "Strict JSON-compatible non-secret uni-next configuration.";
    };
    credentials = {
      vpnPasswordFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Runtime path to the VPN password; never use a Nix store path.";
      };
      logoutUserIDFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Runtime path to the current profile's logout user ID.";
      };
      socksPasswordFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Runtime path to the independent SOCKS password.";
      };
    };
    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open only configured SOCKS listener destinations, sources, and ports.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.credentials.vpnPasswordFile != null;
        message = "services.uni-next.credentials.vpnPasswordFile is required";
      }
      {
        assertion = cfg.credentials.logoutUserIDFile != null;
        message = "services.uni-next.credentials.logoutUserIDFile is required";
      }
      {
        assertion =
          !socksEnabled
          || cfg.credentials.socksPasswordFile != null
          || (!hasRemoteListener && get [ "socks" "allow_loopback_no_auth" ] false);
        message = "SOCKS requires socksPasswordFile unless every listener is loopback and allow_loopback_no_auth is enabled";
      }
      {
        assertion = lib.all (value: !(lib.hasPrefix builtins.storeDir value)) credentialPaths;
        message = "uni-next credential files must be runtime paths outside the Nix store";
      }
      {
        assertion = !hasInlineSecret;
        message = "services.uni-next.settings must not contain inline passwords or logout identifiers";
      }
      {
        assertion = !cfg.openFirewall || !socksEnabled || sources != [ ];
        message = "openFirewall requires socks.allow_sources";
      }
      {
        assertion =
          !cfg.openFirewall || lib.all (value: builtins.length (lib.splitString ":" value) == 2) listeners;
        message = "NixOS firewall generation supports explicit IPv4 SOCKS listeners only";
      }
      {
        assertion = gatewayMode != "netbird" || gatewayInterface != "";
        message = "NetBird gateway mode requires gateway.ingress_interface";
      }
      {
        assertion = gatewayMode != "netbird" || gatewaySources != [ ];
        message = "NetBird gateway mode requires gateway.source_cidrs";
      }
      {
        assertion = gatewayMode != "netbird" || gatewayRoutes != [ ];
        message = "NetBird gateway mode requires gateway.export_routes";
      }
    ];

    users.groups.uni-next = { };
    users.users.uni-next = {
      isSystemUser = true;
      group = "uni-next";
      description = "uni-next VPN client service";
    };

    boot.kernel.sysctl = mkIf (gatewayMode == "netbird") {
      "net.ipv4.ip_forward" = 1;
    };

    networking.nftables.enable = mkIf (
      (cfg.openFirewall && socksEnabled) || (gatewayMode == "netbird" && clampMSS)
    ) true;

    networking.firewall.extraInputRules = mkIf (cfg.openFirewall && socksEnabled) ''
      ${tcpFirewallRules}
      ${lib.optionalString udpEnabled udpFirewallRules}
    '';

    networking.nftables.tables."uni-next-mss" = mkIf (gatewayMode == "netbird" && clampMSS) {
      family = "inet";
      content = ''
        chain forward {
          type filter hook forward priority mangle; policy accept;
          iifname "${gatewayInterface}" oifname "${tunName}" ip saddr ${set gatewaySources} ip daddr ${set gatewayRoutes} tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu comment "uni-next NetBird MSS clamp"
        }
      '';
    };

    systemd.services.uni-next = {
      description = "uni-next VPN client";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ] ++ lib.optional (gatewayMode == "netbird") "netbird.service";
      after = [ "network-online.target" ] ++ lib.optional (gatewayMode == "netbird") "netbird.service";
      startLimitIntervalSec = 300;
      startLimitBurst = 5;
      serviceConfig = {
        Type = "exec";
        ExecStart = "${cfg.package}/bin/uni-next connect --config ${configFile}";
        User = "uni-next";
        Group = "uni-next";
        StateDirectory = "uni-next";
        RuntimeDirectory = "uni-next";
        RuntimeDirectoryMode = "0750";
        StateDirectoryMode = "0750";
        LoadCredential = credentials;
        Restart = "on-failure";
        RestartSec = "10s";
        RestartPreventExitStatus = [
          20
          21
          22
          23
          24
          25
        ];
        TimeoutStopSec = "30s";
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        DevicePolicy = "closed";
        DeviceAllow = [ "/dev/net/tun rw" ];
        NoNewPrivileges = true;
        PrivateDevices = false;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
          "AF_NETLINK"
        ];
        LimitCORE = 0;
      };
    };
  };
}
