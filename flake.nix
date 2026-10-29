{
  description = "uni-next: Go client for a verified Huawei UniVPN profile";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        rec {
          uni-next = pkgs.callPackage ./nix/package.nix { };
          default = uni-next;
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          package = self.packages.${system}.uni-next;
          module = pkgs.callPackage ./nix/checks/module.nix { inherit (nixpkgs.lib) nixosSystem; };
          isolated-network = pkgs.callPackage ./nix/checks/network.nix { };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go
              gopls
              gotools
              iproute2
              nftables
              tcpdump
            ];
          };
        }
      );

      nixosModules.default = import ./nix/module.nix;
    };
}
