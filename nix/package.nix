{
  lib,
  stdenv,
  buildGo125Module,
  fetchFromGitHub,
  installShellFiles,
  src ? null,
}: let
  version =
    if src != null
    then "unstable"
    else "0.4.2";
in
  buildGo125Module {
    pname = "tpm-trust";
    inherit version;

    src =
      if src != null
      then src
      else
        fetchFromGitHub {
          owner = "loicsikidi";
          repo = "tpm-trust";
          tag = "v${version}";
          hash = "sha256-lusfsuUrXZvIbXoiDAOvU8PanbUsMB6eaE2/ARBvybo=";
        };

    vendorHash = "sha256-xDDm5iuYRxgnI9obI1/jNZSS3lxBX02ucdLFx9U+0V4=";

    # Build the main package (at the root)
    # subPackages defaults to [ "." ] if not specified

    ldflags = [
      "-s"
      "-w"
      "-X main.version=${version}"
      "-X main.builtBy=nix"
    ];

    doCheck = true;

    checkFlags = [
      "-v"
      "-timeout=30s"
    ];

    nativeBuildInputs = [installShellFiles];

    postInstall =
      lib.optionalString
      (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
        # Generate shell completions
        installShellCompletion --cmd tpm-trust \
          --bash <($out/bin/tpm-trust completion bash) \
          --zsh <($out/bin/tpm-trust completion zsh) \
          --fish <($out/bin/tpm-trust completion fish)
      '';

    meta = {
      description = "TPM Trust Bundle - manages TPM root certificates bundle";
      homepage = "https://github.com/loicsikidi/tpm-trust";
      license = lib.licenses.bsd3;
      maintainers = [];
      mainProgram = "tpm-trust";
    };
  }
