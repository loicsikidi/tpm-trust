package info

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/loicsikidi/attest/info"
	"github.com/loicsikidi/tpm-trust/internal/log"
)

func TestOutputJSON(t *testing.T) {
	// Redirect stdout to capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	defer func() {
		os.Stdout = oldStdout
	}()

	// Create a sample TPMInfo
	tpmInfo := &info.TPMInfo{
		Vendor:   "test-vendor",
		Revision: "1.54",
		Manufacturer: info.Manufacturer{
			ASCII: "TEST",
			Name:  "Test Manufacturer",
		},
		FirmwareVersion: info.FirmwareVersion{
			Major: 7,
			Minor: 2,
		},
	}

	// Test outputJSON
	err := outputJSON(tpmInfo)
	if err != nil {
		t.Fatalf("outputJSON() failed: %v", err)
	}

	// Close writer and read captured output
	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Verify it's valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("outputJSON() produced invalid JSON: %v", err)
	}

	// Verify key fields
	if result["vendor"] != "test-vendor" {
		t.Errorf("expected vendor to be 'test-vendor', got %v", result["vendor"])
	}

	if result["revision"] != "1.54" {
		t.Errorf("expected revision to be '1.54', got %v", result["revision"])
	}
}

func TestOutputText(t *testing.T) {
	logger := log.New()

	tpmInfo := &info.TPMInfo{
		Vendor:   "test-vendor",
		Revision: "1.54",
		Manufacturer: info.Manufacturer{
			ASCII: "TEST",
			Name:  "Test Manufacturer",
		},
		FirmwareVersion: info.FirmwareVersion{
			Major: 7,
			Minor: 2,
		},
		NVMaxBufferSize: 2048,
		NVIndexMaxSize:  2048,
	}

	// Test outputText - should not return an error
	err := outputText(logger, tpmInfo)
	if err != nil {
		t.Fatalf("outputText() failed: %v", err)
	}
}

func TestOptions_UnsupportedFormat(t *testing.T) {
	// Create a temporary opts with unsupported format
	opts := &options{
		format: "xml",
	}

	err := opts.Check()
	if err == nil {
		t.Fatalf("expected error for unsupported format, got nil")
	}
}
