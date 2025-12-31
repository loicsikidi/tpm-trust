//go:build linux || windows

package privilege

// platformImpl contains platform-specific implementations for privilege elevation.
type platformImpl struct {
	needsElevation func() bool
	elevate        func() error
}

// platform is initialized in elevate_linux.go or elevate_windows.go via init().
var platform platformImpl

// NeedsElevation checks if the current process needs privilege elevation
// to access the TPM device.
//
// On Linux, this checks if the process can access /dev/tpmrm0.
// On Windows, this checks if the process has elevated (administrator) privileges.
func NeedsElevation() bool {
	return platform.needsElevation()
}

// Elevate re-executes the current process with elevated privileges if necessary.
//
// On Linux, this uses sudo to re-execute the process.
// On Windows, this triggers a UAC prompt to re-execute with administrator privileges.
//
// If elevation is successful, this function does not return as the current process
// exits after spawning the elevated process.
func Elevate() error {
	if !NeedsElevation() {
		return nil
	}
	return platform.elevate()
}
