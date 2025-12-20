# tpm-trust

A command-line tool to verify the authenticity of a TPM (Trusted Platform Module) by validating its Endorsement Key (EK) certificate against a trusted bundle of TPM manufacturer root certificates.

## Motivation

This project demonstrates the utility of [tpm-ca-certificates](https://github.com/loicsikidi/tpm-ca-certificates), which provides a single bundle centralizing TPM manufacturer root certificates, making TPM validation straightforward and secure.

> [!NOTE]
> *If you want to know how security is ensured, please read [tpm-ca-certificates's core concepts](https://github.com/loicsikidi/tpm-ca-certificates/tree/main/docs#-core-concepts)*

## Primitives

- 📚 **Read-only TPM operations**: No writes to the TPM, purely verification
- 📜 **Uses `tpm-ca-certificates`**: Leverages native library features
  - Centralized trust roots provided by TPM manufacturers
  - Bundle integrity verification
  - Auto-update of the trust bundle
- 🔒 **Revocation Checking**: `tpm-trust` will by default check if a certificate in EK's chain has been revoked
- 🪶 **Zero Additional Dependencies**: install `tpm-trust` and you are ready to go!

## Requirements

- **Platform**: Linux with TPM 2.0
- **Internet Connection** (for initial setup):
  - Download and verify the trust bundle from `tpm-ca-certificates`
  - Fetch CRLs (if revocation checking is enabled)
  - Download intermediate certificates (if needed)

## Demo

![](cli.gif)

## Usage

<details>
<summary><b>Installation</b></summary>

### Using Go Install

```bash
go install github.com/loicsikidi/tpm-trust@latest
```

### From Source

```bash
git clone https://github.com/loicsikidi/tpm-trust.git
cd tpm-trust
go build -o tpm-trust
sudo mv tpm-trust /usr/local/bin/
```
### Using Nix

For reproducible, declarative installations, use Nix update your `shell.nix` with the following content:

```nix
{ pkgs ? import <nixpkgs> {} }:

let
  tpm-trust = import (fetchTarball "https://github.com/loicsikidi/tpm-trust/archive/main.tar.gz") {};
in
pkgs.mkShell {
  buildInputs = [
    tpm-trust
  ];
}
```

### Shell Completion

`tpm-trust` provides shell completion for bash, zsh, and fish. Enable it for a smoother experience:

**For bash:**
```bash
# Load completion for the current session
source <(tpm-trust completion bash)

# Add to your ~/.bashrc for persistent completion
echo 'source <(tpm-trust completion bash)' >> ~/.bashrc
```

**For zsh:**
```bash
# Load completion for the current session
source <(tpm-trust completion zsh)

# Add to your ~/.zshrc for persistent completion
echo 'source <(tpm-trust completion zsh)' >> ~/.zshrc
```

**For fish:**
```bash
# Load completion for the current session
tpm-trust completion fish | source

# Add to your fish config for persistent completion
tpm-trust completion fish > ~/.config/fish/completions/tpm-trust.fish
```

*Note: when installing via Nix, shell completions are automatically installed to the appropriate directories and should work out of the box.*
</details>

### Audit command

Verify your TPM's authenticity:

```bash
tpm-trust audit
```

> [!TIP]
> If TPM device needs a **sudo** access, the CLI will ask for elevated permissions 💫.

#### Skip Revocation Check

If CRL endpoints are unavailable or you want to skip revocation checking:

```bash
tpm-trust audit --skip-revocation-check
```

#### Verbose Output

Enable detailed logging to see each validation step:

```bash
tpm-trust audit --verbose
```

#### Exit Codes

- `0`: TPM is trusted and verification succeeded
- `1`: TPM is not trusted or validation failed

### Version command

```bash
tpm-trust version
```

## Known Limitations

- **Platform Support**: Only Linux with TPM 2.0 is currently supported
  - I don't plan to support TPM 1.2 as it's largely obsolete
  - Windows support is planned for a future release
- **External EK Certificate URLs**: AMD and Intel TPMs that store EK certificates externally (via URL) are not yet supported due to lack of test hardware
  - If you have AMD/Intel hardware and would like to help test this feature, please [open an issue](https://github.com/loicsikidi/tpm-trust/issues/new) or contact me directly via mail at `rat_9_epics@icloud.com`
- `tpm-ca-certificates` currently only supports a limited set of TPM manufacturers. Check its documentation [here](https://github.com/loicsikidi/tpm-ca-certificates/tree/main/src#vendor-index) for the latest supported vendors.
  * If you need support for a specific TPM manufacturer, please open [an issue](https://github.com/loicsikidi/tpm-ca-certificates/issues/new) in the `tpm-ca-certificates` repository.

> [!TIP]
> You won't need to update `tpm-trust` to get newest bundle version.
>
> *Why?* Internally, `tpm-trust` uses `tpm-ca-certificates` library to always get the latest trust bundle.

## Development

### Prerequisites

```bash
nix-shell
```

This will set up a development environment with all required dependencies.

> [!TIP]
> This will also add git hooks thanks to [githooks.nix](https://github.com/cachix/git-hooks.nix).

### Building

```bash
go build -o tpm-trust
```

### Testing

```bash
# alias provided by nix-shell
gotest
```

### Lint

```bash
# alias provided by nix-shell
lint
```

## License

See [LICENSE](LICENSE) file for details.
