package tpm

import (
	"context"
	"net/http"
	"testing"

	"github.com/loicsikidi/attest"
	"github.com/loicsikidi/attest/endorsement"
)

// TestFetchEKCertFromURLOnRealTPM probes whether the manufacturer's EK certificate URL
// service works for both RSA and ECC key types against the real TPM.
//
// This test requires a physical TPM and is skipped when none is available (e.g., in CI).
// Run it with: go test -v -run TestFetchEKCertFromURLOnRealTPM ./internal/tpm/
func TestFetchEKCertFromURLOnRealTPM(t *testing.T) {
	tpm, err := attest.OpenTPM()
	if err != nil {
		t.Skipf("no TPM available: %v", err)
	}
	t.Cleanup(func() { _ = tpm.Close() })

	tpmInfo, err := tpm.Info()
	if err != nil {
		t.Fatalf("failed to get TPM info: %v", err)
	}
	t.Logf("TPM manufacturer: %s (%s)", tpmInfo.Manufacturer.Name, tpmInfo.Manufacturer.ASCII)

	templates := []struct {
		name string
		tmpl endorsement.Template
	}{
		{"RSA", endorsement.TemplateRSA},
		{"ECC", endorsement.TemplateECC},
	}

	for _, tt := range templates {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			ek, err := endorsement.Get(tpm.Tpm(), endorsement.GetConfig{
				Template: tc.tmpl,
				Info:     *tpmInfo,
			})
			if err != nil {
				t.Logf("endorsement.Get(%s) failed (TPM may not support this key type): %v", tc.name, err)
				return
			}

			t.Logf("CertificateURL for %s EK: %q", tc.name, ek.CertificateURL)

			if ek.CertificateURL == "" {
				t.Logf("manufacturer %q does not provide a %s EK certificate URL — skipping fetch",
					tpmInfo.Manufacturer.ASCII, tc.name)
				return
			}

			cert, err := fetchCertFromURL(context.Background(), ek.CertificateURL, http.DefaultClient)
			if err != nil {
				t.Errorf("fetchCertFromURL() for %s EK: %v", tc.name, err)
				return
			}
			t.Logf("%s EK certificate issuer:  %v", tc.name, cert.Issuer)
			t.Logf("%s EK certificate subject: %v", tc.name, cert.Subject)
		})
	}
}
