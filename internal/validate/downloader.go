package validate

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/loicsikidi/attest/endorsement"
	crlutil "github.com/loicsikidi/tpm-trust/internal/crl"
)

var ErrDownloaderDisabled = errors.New("downloader is disabled")

// httpClient interface is used essentially to mock http.Client in tests
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type downloader struct {
	enabled      bool
	maxDownloads int
	client       httpClient
	timeout      time.Duration
}

//nolint:unused // used in future implementation
type intelEKCertResponse struct {
	Pubhash     string `json:"pubhash"`
	Certificate string `json:"certificate"`
}

func newDefaultDownloader() *downloader {
	return &downloader{
		enabled:      true,
		maxDownloads: 10,
		client:       http.DefaultClient,
		timeout:      2 * time.Second,
	}
}

func (d *downloader) downloadCRL(ctx context.Context, url *url.URL) (crlutil.CRL, error) {
	if !d.enabled {
		// if downloads are disabled, don't try to download at all
		return nil, nil //nolint:nilnil // a nil *x509.RevocationList is valid
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %w", err)
	}
	r, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving CRL from %q: %w", url, err)
	}
	defer r.Body.Close() //nolint:errcheck // ignore error on close

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http request to %q failed with status %d", url, r.StatusCode)
	}

	crlBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading CRL response body: %w", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing CRL from %q: %w", url, err)
	}

	return crlutil.NewCRL(crl)
}

func (d *downloader) downloadCRLSigner(ctx context.Context, url *url.URL) (*x509.Certificate, error) {
	if !d.enabled {
		// if downloads are disabled, don't try to download at all
		return nil, ErrDownloaderDisabled
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %w", err)
	}
	r, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving certificate from %q: %w", url, err)
	}
	defer r.Body.Close() //nolint:errcheck // ignore error on close

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http request to %q failed with status %d", url, r.StatusCode)
	}

	certBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading CRL response body: %w", err)
	}

	// RFC 5280 section 4.2.2.1 states that the certificate
	// is expected to be in DER format in HTTP/FTP.
	crl, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificate from %q: %w", url, err)
	}

	return crl, nil
}

// downloadEKCertificate attempts to download the EK certificate from ekURL.
func (d *downloader) downloadEKCertificate(ctx context.Context, ekURL *url.URL) (*x509.Certificate, error) { //nolint:unused // used in future implementation
	if !d.enabled {
		// if downloads are disabled, don't try to download at all
		return nil, ErrDownloaderDisabled
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ekURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %w", err)
	}

	r, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving EK certificate from %q: %w", ekURL, err)
	}
	defer r.Body.Close() //nolint:errcheck // ignore error on close

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http request to %q failed with status %d", ekURL, r.StatusCode)
	}

	var ekCert *x509.Certificate
	switch {
	case strings.Contains(ekURL.String(), endorsement.IntelEKCertServiceURL): // http and https work; http is redirected to https
		var c intelEKCertResponse
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			return nil, fmt.Errorf("failed decoding EK certificate response: %w", err)
		}
		cb, err := base64.RawURLEncoding.DecodeString(strings.ReplaceAll(c.Certificate, "%3D", "")) // strip padding; decode raw // TODO(lsikidi): this is for Intel; might be different for others
		if err != nil {
			return nil, fmt.Errorf("failed decoding certificate: %w", err)
		}
		ekCert, err = endorsement.ParseEKCertificate(cb)
		if err != nil {
			return nil, fmt.Errorf("failed parsing EK certificate: %w", err)
		}
	case strings.Contains(ekURL.String(), endorsement.AmdEKCertServiceURL): // http and https work
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("failed reading response body: %w", err)
		}
		ekCert, err = endorsement.ParseEKCertificate(body)
		if err != nil {
			return nil, fmt.Errorf("failed parsing EK certificate: %w", err)
		}
	// TODO(lsikidi): does this need cases for ekcert.spserv.microsoft.com, maybe pki.infineon.com?
	// Also see https://learn.microsoft.com/en-us/mem/autopilot/networking-requirements#tpm
	default:
		// TODO(lsikidi): assumption is this is the default logic. For AMD TPMs the same logic is used currently.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("failed reading response body: %w", err)
		}
		ekCert, err = endorsement.ParseEKCertificate(body)
		if err != nil {
			return nil, fmt.Errorf("failed parsing EK certificate: %w", err)
		}
	}
	return ekCert, nil
}
