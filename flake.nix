{
  description = "Qt frontend for the Cloudflare WARP service";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {nixpkgs, ...}: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      config.allowUnfree = true;
    };
    package = pkgs.callPackage ./package.nix {
      warpPackage = pkgs.cloudflare-warp;
    };
  in {
    packages.${system} = {
      default = package;
      warp-gui = package;
    };
    homeManagerModules.default = import ./module.nix;
    checks.${system}.default = package;
  };
}
