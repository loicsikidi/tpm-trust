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
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := runList(t.Context(), tt.getOpts(t))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			if tt.expect != "" && !strings.Contains(output, tt.expect) {
				t.Errorf("expected output to contain '%s', but it didn't.\nFull output:\n%s", tt.expect, output)
			}
		})
	}
}
