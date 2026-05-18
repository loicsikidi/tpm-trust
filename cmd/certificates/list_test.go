package certificates

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/loicsikidi/go-tpm-kit/tpmtest"
	goutils "github.com/loicsikidi/go-utils"
)

func TestListCommand(t *testing.T) {
	baseOpts := &listOptions{
		format: "json",
	}
	tests := []struct {
		name    string
		getOpts func(t *testing.T) *listOptions
		expect  string
	}{
		{
			name: "TPM with 2 EK certificates",
			getOpts: func(t *testing.T) *listOptions {
				opts := goutils.Copy(baseOpts)
				opts.tpm = tpmtest.OpenSimulator(t, tpmtest.OpenConfig{
					SkipCleanup: true, // TPM cleanup is handled by the internal code
				})
				return opts
			},
			expect: `{
  "certificates": [
    {
      "kty": "rsa-2048",
      "issuer": "CN=TPM Simulator Intermediate CA,O=go-tpm-kit"
    },
    {
      "kty": "ecc-nist-p256",
      "issuer": "CN=TPM Simulator Intermediate CA,O=go-tpm-kit"
    }
  ]
}`,
		},
		{
			name: "TPM without EK certificate",
			getOpts: func(t *testing.T) *listOptions {
				opts := goutils.Copy(baseOpts)
				opts.tpm = tpmtest.OpenSimulator(t, tpmtest.OpenConfig{
					SkipProvisioning: true, // disable EK cert provisioning
					SkipCleanup:      true, // TPM cleanup is handled by the internal code
				})
				return opts
			},
			expect: `{
  "certificates": []
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			os.Stdout = w
			t.Cleanup(func() {
				os.Stdout = oldStdout
				_ = r.Close()
				_ = w.Close()
			})

			err = runList(t.Context(), tt.getOpts(t))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if err := w.Close(); err != nil {
				t.Fatalf("failed to close stdout writer: %v", err)
			}

			// Read captured output
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, r); err != nil {
				t.Fatalf("failed to read captured stdout: %v", err)
			}
			output := buf.String()

			if tt.expect != "" && !strings.Contains(output, tt.expect) {
				t.Errorf("expected output to contain '%s', but it didn't.\nFull output:\n%s", tt.expect, output)
			}
		})
	}
}
