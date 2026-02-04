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
// On Linux, this function re-executes the process using sudo if needed.
// If elevation is successful, this function does not return as the current process
// exits after spawning the elevated process.
//
// On Windows, this function returns an error as automatic privilege elevation
// is not supported. Users must run the CLI from an administrator terminal
// (Run as Administrator).
func Elevate() error {
	if !needsElevation() {
		return nil
	}
	return platform.elevate()
}
