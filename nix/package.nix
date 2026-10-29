{ lib, buildGoModule }:

buildGoModule {
  pname = "uni-next";
  version = "0.1.0";

  src = import ./source.nix { inherit lib; };

  vendorHash = import ./vendor-hash.nix { inherit lib; };
  subPackages = [ "cmd/uni-next" ];

  ldflags = [
    "-s"
    "-w"
    "-X main.version=0.1.0"
  ];

  doCheck = true;

  meta = {
    description = "uni-next Linux client for the verified CNEM profile";
    mainProgram = "uni-next";
    platforms = lib.platforms.linux;
  };
}
