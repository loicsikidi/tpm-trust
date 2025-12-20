package validate

import (
	"context"
	"net/url"
	"testing"

	tpmtest "github.com/loicsikidi/tpm-trust/internal/validate/testutil"
)

func Test_downloadCRLSigner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		enabled bool
		url     string
		wantErr bool
	}{
		{
			name:    "success",
			enabled: true,
			url:     "http://pki/signer.cer",
			wantErr: false,
		},
		{
			name:    "disabled downloader",
			enabled: false,
			url:     "http://pki/signer.cer",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client *tpmtest.MockClient
			if tc.enabled {
				client = tpmtest.NewDefaultDowloaderMockClient(t)
			}

			d := &downloader{
				enabled:      tc.enabled,
				maxDownloads: 10,
				client:       client,
			}

			certURL, err := url.Parse(tc.url)
			if err != nil {
				t.Fatalf("failed to parse URL: %v", err)
			}

			got, err := d.downloadCRLSigner(context.Background(), certURL)
			if (err != nil) != tc.wantErr {
				t.Errorf("downloader.downloadCRLSigner() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if err == nil {
				if got == nil {
					t.Error("downloader.downloadCRLSigner() returned nil certificate")
					return
				}
				if len(got.Raw) == 0 {
					t.Error("downloader.downloadCRLSigner() returned empty certificate")
					return
				}
			}
		})
	}
}

func Test_downloadEKCertifiate(t *testing.T) {
	t.Parallel()
	client := tpmtest.NewDefaultDowloaderMockClient(t)
	tests := []struct {
		name        string
		ctx         context.Context
		ekURL       string
		wantSubject string
		wantErr     bool
	}{
		{
			name:        "intel",
			ctx:         context.Background(),
			ekURL:       "https://ekop.intel.com/ekcertservice/WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D",
			wantSubject: "", // no subject in EK certificate
			wantErr:     false,
		},
		{
			name:        "amd EK CA root",
			ctx:         context.Background(),
			ekURL:       "https://ftpm.amd.com/pki/aia/264D39A23CEB5D5B49D610044EEBD121",            // assumes AMD EK certificate responses are all in the same format
			wantSubject: "CN=AMDTPM,OU=Engineering,O=Advanced Micro Devices,L=Sunnyvale,ST=CA,C=US", // AMDTPM EK CA root subject
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := &downloader{enabled: true, maxDownloads: 10, client: client}
			ekURL, err := url.Parse(tc.ekURL)
			if err != nil {
				t.Fatalf("failed to parse URL: %v", err)
			}

			got, err := d.downloadEKCertificate(tc.ctx, ekURL)
			if (err != nil) != tc.wantErr {
				t.Errorf("downloader.downloadEKCertifiate() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if err == nil {
				if got == nil {
					t.Error("downloader.downloadEKCertifiate() returned nil certificate")
					return
				}
				if len(got.Raw) == 0 {
					t.Error("downloader.downloadEKCertifiate() returned empty certificate")
					return
				}
				if got.Subject.String() != tc.wantSubject {
					t.Errorf("downloader.downloadEKCertifiate() = %v, want %v", got.Subject.String(), tc.wantSubject)
				}
			}
		})
	}
}
