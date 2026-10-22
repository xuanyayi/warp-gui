{
  lib,
  stdenvNoCC,
  python3,
  qt6,
  makeDesktopItem,
  warpPackage,
}: let
  python = python3.withPackages (ps: [ps.pyqt6]);
  desktopItem = makeDesktopItem {
    name = "cloudflare-warp";
    desktopName = "Cloudflare WARP";
    genericName = "Cloudflare WARP VPN";
    comment = "Manage the Cloudflare WARP connection";
    exec = "warp-gui";
    icon = "cloudflare-warp";
    terminal = false;
    startupNotify = true;
    startupWMClass = "warp-gui";
    categories = ["Network" "Utility"];
  };
in
  stdenvNoCC.mkDerivation {
    pname = "warp-gui";
    version = "1.0";
    src = lib.fileset.toSource {
      root = ./.;
      fileset = lib.fileset.unions [./warp-gui.py ./cloudflare-warp.svg ./tests];
    };

    nativeBuildInputs = [python qt6.wrapQtAppsHook];
    buildInputs = [qt6.qtbase qt6.qtwayland];
    dontConfigure = true;
    dontBuild = true;
    # The Qt hook automatically wraps ELF binaries; wrap this Python script explicitly.
    dontWrapQtApps = true;
    doCheck = true;

    checkPhase = ''
      runHook preCheck
      export QT_QPA_PLATFORM=offscreen
      export PYTHONDONTWRITEBYTECODE=1
      ${python}/bin/python3 -m unittest discover -s tests -v
      runHook postCheck
    '';

    installPhase = ''
      runHook preInstall
      install -Dm755 warp-gui.py "$out/bin/warp-gui"
      substituteInPlace "$out/bin/warp-gui" \
        --replace-fail 'WARP_CLI = "warp-cli"' 'WARP_CLI = "${lib.getExe' warpPackage "warp-cli"}"'
      patchShebangs "$out/bin/warp-gui"
      install -Dm644 cloudflare-warp.svg "$out/share/icons/hicolor/scalable/apps/cloudflare-warp.svg"
      install -Dm644 ${desktopItem}/share/applications/cloudflare-warp.desktop "$out/share/applications/cloudflare-warp.desktop"
      substituteInPlace "$out/share/applications/cloudflare-warp.desktop" \
        --replace-fail 'Exec=warp-gui' "Exec=$out/bin/warp-gui"
      runHook postInstall
    '';

    preFixup = ''
      wrapQtApp "$out/bin/warp-gui"
    '';

    meta = {
      description = "Qt frontend for the Cloudflare WARP service";
      mainProgram = "warp-gui";
      platforms = lib.platforms.linux;
    };
  }
