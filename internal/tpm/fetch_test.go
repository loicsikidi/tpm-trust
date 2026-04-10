package tpm

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// amdEKCertBase64 is a base64-encoded AMD EK CA root certificate used as a
// representative DER response for testing the HTTP fetch logic.
// Source: ftpm.amd.com (same cert referenced in internal/validate/testutil).
const amdEKCertBase64 = `
MIIEiDCCA3CgAwIBAgIQJk05ojzrXVtJ1hAETuvRITANBgkqhkiG9w0BAQsFADB2MRQwEgYDVQQL
EwtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxEjAQBgNVBAcTCVN1bm55dmFsZTELMAkGA1UECBMC
Q0ExHzAdBgNVBAoTFkFkdmFuY2VkIE1pY3JvIERldmljZXMxDzANBgNVBAMTBkFNRFRQTTAeFw0x
NDEwMjMxNDM0MzJaFw0zOTEwMjMxNDM0MzJaMHYxFDASBgNVBAsTC0VuZ2luZWVyaW5nMQswCQYD
VQQGEwJVUzESMBAGA1UEBxMJU3Vubnl2YWxlMQswCQYDVQQIEwJDQTEfMB0GA1UEChMWQWR2YW5j
ZWQgTWljcm8gRGV2aWNlczEPMA0GA1UEAxMGQU1EVFBNMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAssnOAYu5nRflQk0bVtsTFcLSAMx9odZ4Ey3n6/MA6FD7DECIE70RGZgaRIID0eb+
dyX3znMrp1TS+lD+GJSw7yDJrKeU4it8cMLqFrqGm4SEx/X5GBa11sTmL4i60pJ5nDo2T69OiJ+
iqYzgBfYJLqHQaeSRN6bBYyn3w1H4JNzPDNvqKHvkPfYewHjUAFJAI1dShYO8REnNCB8eeolj375
nymfAAZzgA8v7zmFX/1tVLCy7Mm6n7zndT452TB1mek9LC5LkwlnyABwaN2Q8LV4NWpIAzTgr55x
bU5VvgcIpw+/qcbYHmqL6ZzCSeE1gRKQXlsybK+W4phCtQfMgHQIDAQABo4IBEDCCAQwwDgYDVR0P
AQH/BAQDAgEGMCMGCSsGAQQBgjcVKwQWBBRXjFRfeWlRQhIhpKV4rNtfaC+JyDAdBgNVHQ4EFgQU
V4xUX3lpUUISIaSleKzbX2gvicgwDwYDVR0TAQH/BAUwAwEB/zA4BggrBgEFBQcBAQQsMCowKAYI
KwYBBQUHMAGGHGh0dHA6Ly9mdHBtLmFtZC5jb20vcGtpL29jc3AwLAYDVR0fBCUwIzAhoB+gHYYb
aHR0cDovL2Z0cG0uYW1kLmNvbS9wa2kvY3JsMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUF
BwIBFhxodHRwczovL2Z0cG0uYW1kLmNvbS9wa2kvY3BzMA0GCSqGSIb3DQEBCwUAA4IBAQCWB9yA
oYYIt5HRY/OqJ5LUacP6rNmsMfPUDTcahXB3iQmY8HpUoGB23lhxbq+kz3vIiGAcUdKHlpB/epXy
hABGTcJrNPMfx9akLqhI7WnMCPBbHDDDzKjjMB3Vm65PFbyuqbLujN/sN6kNtc4hL5r5Pr6Mze5H
9WXBo2F2Oy+7+9jWMkxNrmUhoUUrF/6YsajTGPeq7r+i6q84W2nJdd+BoQQv4sk5GeuN2j2u4k1a
8DkRPsVPc2I9QTtbzekchTK1GCXWki3DKGkZUEuaoaa60Kgw55Q5rt1eK7HKEG5npmR8aEod7BDL
Wy4CMTNAWR5iabCW/KX28JbJL6Phau9j`

func mustDecodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	// Strip whitespace introduced by raw string literals.
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.TrimSpace(s)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	return b
}

func TestFetchCertFromURL(t *testing.T) {
	t.Parallel()

	certDER := mustDecodeBase64(t, amdEKCertBase64)

	tests := []struct {
		name        string
		handler     http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name: "success/amd-rsa",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.Copy(w, bytes.NewReader(certDER))
			},
		},
		{
			name: "error/http-404",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr:     true,
			errContains: "unexpected HTTP 404",
		},
		{
			name: "error/http-500",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr:     true,
			errContains: "unexpected HTTP 500",
		},
		{
			name: "error/invalid-cert-data",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "not a valid DER certificate")
			},
			wantErr:     true,
			errContains: "failed to parse EK certificate",
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(tc.handler)
			t.Cleanup(srv.Close)

			cert, err := fetchCertFromURL(context.Background(), srv.URL, http.DefaultClient)
			if (err != nil) != tc.wantErr {
				t.Errorf("fetchCertFromURL() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if tc.wantErr {
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("fetchCertFromURL() error = %v, want to contain %q", err, tc.errContains)
				}
				return
			}
			if cert == nil {
				t.Error("fetchCertFromURL() returned nil certificate on success")
			}
		})
	}
}
