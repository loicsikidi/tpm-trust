//go:build windows

package windowsexec

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go exec.go
//sys shellExecuteExW(info *shellExecuteInfoW) (err error) [failretval==0] = shell32.ShellExecuteExW

// shellExecuteInfoW is the input/output struct for ShellExecuteExW.
// See: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow
type shellExecuteInfoW struct {
	cbSize         uint32
	fMask          uint32
	hwnd           windows.Handle
	lpVerb         uintptr
	lpFile         uintptr
	lpParameters   uintptr
	lpDirectory    uintptr
	nShow          int
	hInstApp       windows.Handle
	lpIDList       uintptr
	lpClass        uintptr
	hkeyClass      windows.Handle
	dwHotKey       uint32
	hIconOrMonitor windows.Handle
	hProcess       windows.Handle
}

const (
	// SEE_MASK_NOCLOSEPROCESS (0x00000040):
	// Use to indicate that the hProcess member receives the process handle.
	// This handle is typically used to allow an application to find out when a
	// process created with ShellExecuteEx terminates. The calling application
	// is responsible for closing the handle when it is no longer needed.
	SEE_MASK_NOCLOSEPROCESS = 0x40
)

// RunAsAndWait uses ShellExecuteExW to create a new process with elevated
// privileges on Windows via UAC prompt. It waits for the process to exit,
// or until timeout is exhausted. It returns an error if the process exits
// with a non-zero status code.
func RunAsAndWait(
	file, directory string,
	timeout time.Duration,
	parameters []string,
) error {
	// Convert string inputs to UTF16 pointers for Windows API
	lpVerb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return fmt.Errorf("converting verb to ptr: %w", err)
	}
	lpFile, err := windows.UTF16PtrFromString(file)
	if err != nil {
		return fmt.Errorf("converting file to ptr: %w", err)
	}
	lpDirectory, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return fmt.Errorf("converting directory to ptr: %w", err)
	}
	lpParameters, err := windows.UTF16PtrFromString(strings.Join(parameters, " "))
	if err != nil {
		return fmt.Errorf("converting parameters to ptr: %w", err)
	}

	// Prepare ShellExecuteExW structure
	// https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw
	info := &shellExecuteInfoW{
		fMask:        SEE_MASK_NOCLOSEPROCESS,
		lpVerb:       uintptr(unsafe.Pointer(lpVerb)),
		lpFile:       uintptr(unsafe.Pointer(lpFile)),
		lpParameters: uintptr(unsafe.Pointer(lpParameters)),
		lpDirectory:  uintptr(unsafe.Pointer(lpDirectory)),
		nShow:        windows.SW_NORMAL,
	}
	info.cbSize = uint32(unsafe.Sizeof(*info))

	if err := shellExecuteExW(info); err != nil {
		// Log additional context from hInstApp for debugging
		slog.DebugContext(context.Background(), "Error calling shellExecuteExW",
			"err", err,
			"h_inst_app", info.hInstApp,
		)
		return fmt.Errorf("calling shellExecuteExW: %w", err)
	}

	if info.hProcess == 0 {
		return fmt.Errorf("unexpected null hProcess handle from shellExecuteExW")
	}

	// We're responsible for closing the process handle
	defer windows.CloseHandle(info.hProcess)

	// Calculate wait time
	waitTime := windows.INFINITE
	if timeout > 0 {
		waitTime = int(timeout.Milliseconds())
	}

	// Wait for the elevated process to finish
	w, err := windows.WaitForSingleObject(info.hProcess, uint32(waitTime))
	if err != nil {
		return fmt.Errorf("waiting for elevated process: %w", err)
	}

	switch w {
	case windows.WAIT_OBJECT_0:
		// Process exited normally
	case uint32(windows.WAIT_TIMEOUT):
		return fmt.Errorf("timed out waiting for elevated process")
	default:
		return fmt.Errorf("unexpected wait result: %d", w)
	}

	// Check the exit code of the elevated process
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return fmt.Errorf("getting exit code: %w", err)
	}

	if code != 0 {
		return fmt.Errorf("elevated process exited with code: %d", code)
	}

	return nil
}
