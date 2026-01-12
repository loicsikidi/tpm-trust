//go:build linux || windows

package privilege

// platformImpl contains platform-specific implementations for privilege elevation.
type platformImpl struct {
	needsElevation func() bool
	elevate        func() error
}

// platform is initialized in elevate_linux.go or elevate_windows.go via init().
var platform platformImpl

// needsElevation checks if the current process needs privilege elevation
// to access the TPM device.
func needsElevation() bool {
	return platform.needsElevation()
}

// Elevate re-executes the current process with elevated privileges if necessary.
//
// This feature is only required on Linux.
//
// If elevation is successful, this function does not return as the current process
// exits after spawning the elevated process.
func Elevate() error {
	if !needsElevation() {
		return nil
	}
	return platform.elevate()
}
