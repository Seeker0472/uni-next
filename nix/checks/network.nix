{ lib, pkgs }:

let
  package = pkgs.callPackage ../package.nix { };
  testBinaries = pkgs.buildGoModule {
    pname = "univpn-network-tests";
    version = "0.1.0";
    src = import ../source.nix { inherit lib; };
    vendorHash = import ../vendor-hash.nix { inherit lib; };
    doCheck = false;
    buildPhase = ''
      runHook preBuild
      mkdir -p build
      go test -c -o build/protocol.test ./internal/protocol/univpn
      go test -c -o build/socks5.test ./internal/socks5
      go test -c -o build/network-linux.test ./internal/network/linux
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      mkdir -p "$out/bin"
      cp build/*.test "$out/bin/"
      runHook postInstall
    '';
  };
in
pkgs.testers.runNixOSTest {
  name = "univpn-isolated-network";
  nodes.machine =
    { lib, ... }:
    {
      imports = [ ../module.nix ];
      boot.kernelModules = [
        "tun"
        "nf_conntrack"
      ];
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
      systemd.services.univpn.wantedBy = lib.mkForce [ ];
    };
  testScript = ''
    machine.start()
    machine.succeed("test \"$(sysctl -n net.ipv4.ip_forward)\" = 1")
    nft = machine.wait_until_succeeds("nft list chain inet univpn-mss forward")
    assert "tcp option maxseg size set rt mtu" in nft, nft
    protocol = machine.succeed("${testBinaries}/bin/protocol.test -test.v -test.run '^TestClientCompletesVerifiedLocalProtocolExchange$'")
    assert "--- PASS: TestClientCompletesVerifiedLocalProtocolExchange" in protocol, protocol
    socks = machine.succeed("${testBinaries}/bin/socks5.test -test.v -test.run '^TestServerRelaysAuthorizedTCPAndUDP$'")
    assert "--- PASS: TestServerRelaysAuthorizedTCPAndUDP" in socks, socks
    network = machine.succeed("UNIVPN_TEST_NET_ADMIN=1 ${testBinaries}/bin/network-linux.test -test.v -test.run '^TestLeaseLifecycleInIsolatedNamespace$'")
    assert "--- PASS: TestLeaseLifecycleInIsolatedNamespace" in network, network
  '';
}
