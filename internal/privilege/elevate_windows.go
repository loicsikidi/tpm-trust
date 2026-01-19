//go:build windows

package privilege

import (
	"errors"

	"golang.org/x/sys/windows"
)

func init() {
	platform = platformImpl{
		needsElevation: needsElevationWindows,
		elevate:        elevateWindows,
	}
}

func needsElevationWindows() bool {
	return !windows.GetCurrentProcessToken().IsElevated()
}

func elevateWindows() error {
	return errors.New("privilege elevation is not supported on Windows: please run the CLI from an administrator terminal (Run as Administrator)")
}
