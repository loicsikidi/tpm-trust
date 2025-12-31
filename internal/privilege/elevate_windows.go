//go:build windows

package privilege

import (
	"fmt"
	"os"
	"time"

	"github.com/caarlos0/log"
	"github.com/loicsikidi/tpm-trust/internal/windowsexec"
	"golang.org/x/sys/windows"
)

func init() {
	platform = platformImpl{
		needsElevation: needsElevationWindows,
		elevate:        elevateWindows,
	}
}

// needsElevationWindows checks if the current process has elevated (administrator) privileges.
func needsElevationWindows() bool {
	token := windows.GetCurrentProcessToken()
	return !token.IsElevated()
}

// elevateWindows re-executes the current process with elevated privileges via UAC prompt.
// It preserves all command-line arguments and returns an error if elevation fails.
func elevateWindows() error {
	log.Warn("TPM access requires elevated privileges, triggering UAC prompt")

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Use a generous timeout to account for UAC interaction and program execution.
	// The user may take time to respond to the UAC prompt.
	timeout := 5 * time.Minute

	if err := windowsexec.RunAsAndWait(executable, cwd, timeout, os.Args[1:]); err != nil {
		return fmt.Errorf("failed to re-execute with elevated privileges: %w", err)
	}

	// If we reach here, the elevated process completed successfully.
	// Exit the current (non-elevated) process.
	os.Exit(0)
	return nil
}
