//go:build windows

package privilege

import (
	"errors"
)

func init() {
	platform = platformImpl{
		// Windows doesn't need elevation
		needsElevation: needsElevationWindows,
		elevate:        elevateWindows,
	}
}

func needsElevationWindows() bool {
	return false
}

func elevateWindows() error {
	return errors.ErrUnsupported
}
