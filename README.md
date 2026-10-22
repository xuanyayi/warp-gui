# Warp GUI

Python/PyQt6 frontend for the Cloudflare WARP system service.

- Build: `nix build`
- Test (including Qt offscreen unit tests): `nix flake check`
- Package: `packages.x86_64-linux.default` (also `warp-gui`)
- Home Manager: `homeManagerModules.default`

Import the Home Manager module through NixOS Home Manager integration and
set `services.cloudflare-warp.enable = true` in the NixOS configuration.
The module uses `osConfig.services.cloudflare-warp.package` for `warp-cli`
and asserts that the system service is enabled. The standalone package uses
`pkgs.cloudflare-warp`. Cloudflare WARP requires unfree packages.

Consumers should make this input's `nixpkgs` follow their own `nixpkgs`.
The module builds with the consumer's `pkgs`, including its package policy.

Private Git+SSH consumers need repository read access when resolving or
fetching the input. Keep authentication outside Nix expressions and the store.
