{ lib, buildGoModule }:

buildGoModule {
  pname = "univpn";
  version = "0.1.0";

  src = import ./source.nix { inherit lib; };

  vendorHash = import ./vendor-hash.nix { inherit lib; };
  subPackages = [ "cmd/univpn" ];

  ldflags = [
    "-s"
    "-w"
    "-X main.version=0.1.0"
  ];

  doCheck = true;

  meta = {
    description = "Linux client for the verified Huawei UniVPN CNEM base profile";
    mainProgram = "univpn";
    platforms = lib.platforms.linux;
  };
}
