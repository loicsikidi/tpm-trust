package privilege

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/caarlos0/log"
)

const (
	tpmDevicePath = "/dev/tpmrm0"
)

// NeedsElevation checks if the current process needs privilege elevation
// to access the TPM device.
func NeedsElevation() bool {
	if os.Geteuid() == 0 {
		return false
	}

	if _, err := os.Stat(tpmDevicePath); err != nil {
		return true
	}

	file, err := os.OpenFile(tpmDevicePath, os.O_RDWR, 0)
	if err != nil {
		return true
	}
	file.Close()
	return false
}

// Elevate re-executes the current process with elevated privileges using sudo.
// It preserves all command-line arguments and returns an error if elevation fails.
func Elevate() error {
	if !NeedsElevation() {
		return nil
	}

	log.Warn("TPM access requires elevated privileges, re-executing with sudo")

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	args := append([]string{executable}, os.Args[1:]...)
	cmd := exec.Command("sudo", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
		}
		return fmt.Errorf("failed to re-execute with sudo: %w", err)
	}

	os.Exit(0)
	return nil
}
