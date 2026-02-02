{
  pkgs ?
    import (fetchTarball
      "https://github.com/NixOS/nixpkgs/archive/f665af0cdb70ed27e1bd8f9fdfecaf451260fc55.tar.gz")
    {},
}: let
  helpers = import (builtins.fetchTarball
    "https://github.com/loicsikidi/nix-shell-toolbox/tarball/main") {
    inherit pkgs;
    hooksConfig = {
      gotest.settings.flags = "-race";
    };
  };
in
  pkgs.mkShell {
    buildInputs = with pkgs;
      [
        delve
        goreleaser
        cosign
        syft
        gcc
      ]
      ++ helpers.packages;

    shellHook = ''
      ${helpers.shellHook}
      echo "Development environment ready!"
      echo "  - Go version: $(go version)"
    '';

    # to enable debugging with delve
    hardeningDisable = ["fortify"];

    env = {
      CGO_ENABLED = "1";
    };
  }
