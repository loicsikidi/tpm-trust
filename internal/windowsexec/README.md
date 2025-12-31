# windowsexec

This package provides Windows-specific functionality for executing processes with elevated privileges via UAC (User Account Control).

## Overview

The `windowsexec` package wraps the Windows API function `ShellExecuteExW` to enable privilege elevation on Windows systems. This is used by `tpm-trust` to request administrator privileges when accessing TPM hardware that requires elevated permissions.

## Code Generation

The `zsyscall_windows.go` file contains low-level syscall bindings and is **automatically generated**. Do not edit it manually.

### Why code generation?

Go doesn't provide direct bindings for all Windows API functions. The `mkwinsyscall` tool from `golang.org/x/sys/windows` generates the necessary glue code to call Windows DLL functions from Go.

In our case, we need to call `ShellExecuteExW` from `shell32.dll` to trigger UAC prompts.

### How to regenerate

If you modify the `//sys` directive in `exec.go`, regenerate the bindings:

```bash
cd internal/windowsexec
go generate
```

Or manually:

```bash
go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go exec.go
```

### What triggers regeneration?

The `//go:generate` directive in `exec.go` specifies the generation command:

```go
//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go exec.go
```

When you run `go generate`, it:
1. Parses `exec.go` for `//sys` directives
2. Generates syscall wrapper code in `zsyscall_windows.go`
3. Creates the necessary DLL bindings

## Usage

This package is only compiled on Windows (via `//go:build windows` build tag).

### Example

```go
import "github.com/loicsikidi/tpm-trust/internal/windowsexec"

// Re-execute current program with elevated privileges
err := windowsexec.RunAsAndWait(
    executable,      // Path to executable
    workingDir,      // Working directory
    5 * time.Minute, // Timeout
    []string{"arg1", "arg2"}, // Arguments
)
```

This will:
1. Trigger a UAC prompt asking for administrator privileges
2. Launch the specified executable with elevated rights
3. Wait for the process to complete (or timeout)
4. Return the exit code

## Technical Details

### ShellExecuteExW

We use `ShellExecuteExW` (Unicode version) with the `"runas"` verb to request elevation:

- **lpVerb**: `"runas"` triggers UAC prompt
- **fMask**: `SEE_MASK_NOCLOSEPROCESS` allows us to wait for process completion
- **nShow**: `SW_NORMAL` shows the window normally

See Microsoft documentation:
- [ShellExecuteExW function](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
- [SHELLEXECUTEINFOW structure](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow)

### Build Tags

This entire package uses `//go:build windows` to ensure it's only compiled on Windows platforms. The build system automatically excludes it when building for Linux or other platforms.

## Testing

Since this package depends on Windows APIs, it cannot be tested in cross-compilation or on non-Windows systems. Unit tests would require:

- Running on actual Windows
- Mocking the syscall layer (complex and not very useful)

Instead, we rely on integration testing with the parent `privilege` package.

## Troubleshooting

### "cannot find module golang.org/x/sys/windows/mkwinsyscall"

The tool will be automatically downloaded when you run `go generate`. If you want to install it explicitly:

```bash
go install golang.org/x/sys/windows/mkwinsyscall@latest
```

### UAC prompt doesn't appear

- Ensure the executable path is absolute
- Check that UAC is enabled on the system (rarely disabled)
- Verify the process isn't already elevated

### Process hangs

- Check the timeout value (default: 5 minutes)
- Ensure the elevated process completes successfully
- Check for deadlocks in stdin/stdout/stderr handling

## References

- [Teleport's windowsexec implementation](https://github.com/gravitational/teleport/tree/master/lib/windowsexec) (inspiration)
- [Windows UAC Documentation](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/)
