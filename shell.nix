{
  pkgs ?
    import (fetchTarball
      # pin nixpkgs in order to use go v1.26.0
      "https://github.com/NixOS/nixpkgs/archive/80d901ec0377e19ac3f7bb8c035201e2e098cc97.tar.gz")
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
