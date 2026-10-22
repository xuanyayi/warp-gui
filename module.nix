{
  pkgs,
  osConfig,
  ...
}: let
  warpGuiPkg = pkgs.callPackage ./package.nix {
    warpPackage = osConfig.services.cloudflare-warp.package;
  };
in {
  assertions = [
    {
      assertion = osConfig.services.cloudflare-warp.enable;
      message = "warp-gui requires the Cloudflare WARP system service";
    }
  ];

  home.packages = [warpGuiPkg];
}
