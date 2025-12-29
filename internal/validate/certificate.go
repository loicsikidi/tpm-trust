package validate

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/caarlos0/log"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
	"github.com/loicsikidi/tpm-trust/internal/sliceutil"
)

var (
	ErrUntrustedCertificate = errors.New("EK certificate trust could not be established")
	ErrCertificateRevoked   = errors.New("certificate is revoked")
	ErrEKCannotBeCA         = errors.New("EK certificate cannot be a CA certificate")
)

var (
	// OID defined in TCG EK Credential Profile, version 2.6
	// See section 3.2.16 "Extended Key Usage"
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf#page=32
	EKCertificate = []int{2, 23, 133, 8, 1}
)

type Checker interface {
	Check(cfg CheckConfig) error
}

type ekchecker struct {
	downloader *downloader
	tb         apiv1beta.TrustedBundle
	logger     *log.Logger
}

type EKCheckerConfig struct {
	Downloader    *downloader
	TrustedBundle apiv1beta.TrustedBundle
	Timeout       time.Duration
	Logger        *log.Logger
}

func (e *EKCheckerConfig) CheckAndSetDefaults() error {
	if e.Logger == nil {
		e.Logger = log.New(os.Stdout)
	}
	if e.Timeout == 0 {
		e.Timeout = 5 * time.Second
	}
	if e.Downloader == nil {
		e.Downloader = newDefaultDownloader()
	}
	if e.TrustedBundle == nil {
		ctx, cancel := context.WithTimeout(context.Background(), e.Timeout)
		defer cancel()
		var err error
		cfg := apiv1beta.GetConfig{AutoUpdate: apiv1beta.AutoUpdateConfig{DisableAutoUpdate: true}}
		e.TrustedBundle, err = apiv1beta.GetTrustedBundle(ctx, cfg)
		if err != nil {
			return err
		}
	}
	e.Downloader.timeout = e.Timeout
	return nil
}

func NewEKChecker(cfg EKCheckerConfig) (Checker, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &ekchecker{
		downloader: cfg.Downloader,
		tb:         cfg.TrustedBundle,
		logger:     cfg.Logger,
	}, nil
}

type CheckConfig struct {
	EK                  *x509.Certificate
	SkipRevocationCheck bool
}

func (c *CheckConfig) CheckAndSetDefaults() error {
	if c.EK == nil {
		return fmt.Errorf("EK certificate must be provided")
	}
	return nil
}

func (c *ekchecker) Check(cfg CheckConfig) error {
	c.logger.IncreasePadding()
	defer c.logger.DecreasePadding()

	if err := cfg.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid check config: %w", err)
	}
	if err := c.check(&cfg); err != nil {
		return err
	}

	issuers, err := c.getIssuerCertificates(c.downloader, cfg.EK)
	if err != nil {
		return err
	}

	if !cfg.SkipRevocationCheck {
		crlUrls, err := c.prepareUrls(cfg.EK.CRLDistributionPoints)
		if err != nil {
			return fmt.Errorf("failed to prepare CRL URLs: %w", err)
		}

		for _, url := range crlUrls {
			ctx, cancel := context.WithTimeout(context.Background(), c.downloader.timeout)
			defer cancel()

			crl, err := c.downloader.downloadCRL(ctx, url)
			if err != nil {
				return fmt.Errorf("failed to download CRL from %q: %w", url, err)
			}

			if err := crl.Verify(issuers...); err != nil {
				return fmt.Errorf("failed to verify CRL: %w", err)
			}

			if crl.IsRevoked(cfg.EK) {
				return ErrCertificateRevoked
			}
		}
	}

	// TODO(lsikidi): create dynamic intermediate pool if the issuers is not yet supported
	// in the trusted bundle?
	for _, issuer := range filterIntermediates(issuers) {
		if !c.tb.Contains(issuer) {
			c.logger.WithField("subject", issuer.Subject.String()).Debug("missing cert in trusted bundle")
		}
	}
	if err := c.tb.VerifyCertificate(cfg.EK); err != nil {
		c.logger.WithError(err).Debug("certificate verification error")
		c.logger.WithField("status", "untrusted").
			Error("certificate")
		return fmt.Errorf("%w: %v", ErrUntrustedCertificate, err)
	}
	c.logger.WithField("status", "trusted").Info("certificate")
	return nil
}

func (c *ekchecker) check(cfg *CheckConfig) error {
	switch {
	case cfg.EK.IsCA:
		return ErrEKCannotBeCA
	case len(cfg.EK.IssuingCertificateURL) == 0:
		return fmt.Errorf("EK certificate does not contain AIA extension with issuing certificate URL")
	// an arbitrary limit, so that we don't start making a large number of HTTP requests (if needed)
	case len(cfg.EK.IssuingCertificateURL) > c.downloader.maxDownloads:
		return fmt.Errorf("number of Issuers (%d) bigger than the maximum allowed number (%d) of downloads", len(cfg.EK.CRLDistributionPoints), c.downloader.maxDownloads)
	case !cfg.SkipRevocationCheck && len(cfg.EK.CRLDistributionPoints) > c.downloader.maxDownloads:
		return fmt.Errorf("number of CRLs (%d) bigger than the maximum allowed number (%d) of downloads", len(cfg.EK.CRLDistributionPoints), c.downloader.maxDownloads)
	}
	if len(cfg.EK.CRLDistributionPoints) == 0 {
		c.logger.WithField("outcome", "revocation check will be skipped").Warn("missing CRL DP")
		cfg.SkipRevocationCheck = true
	}
	if len(cfg.EK.UnhandledCriticalExtensions) > 0 {
		c.logger.WithField("extensions", cfg.EK.UnhandledCriticalExtensions).
			Debug("found: unhandled critical extensions")
	}
	found := false
	for _, ext := range cfg.EK.UnknownExtKeyUsage {
		if slices.Equal(ext, EKCertificate) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("EK certificate does not contain the required EK OID in Extended Key Usage")
	}
	return nil
}

func (c *ekchecker) prepareUrls(urls []string) ([]*url.URL, error) {
	var crlURLs []*url.URL
	for _, u := range urls {
		parsedURL, err := url.Parse(u)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CRL URL %q: %w", u, err)
		}

		// we only support HTTP protocols (at least for now)
		if !slices.Contains([]string{"http", "https"}, parsedURL.Scheme) {
			c.logger.WithField("scheme", parsedURL.Scheme).
				WithField("endpoint", parsedURL.String()).
				Warn("unsupported scheme: skipping")
			continue
		}
		crlURLs = append(crlURLs, parsedURL)
	}
	return crlURLs, nil
}

// getIssuerCertificates retrieves the issuer certificates for the EK certificates.
// it's a strict function that expects to get all the issuer certificates
//
// TODO(lsikidi): support recursive issuer fetching for deeper chains
func (c *ekchecker) getIssuerCertificates(downloader *downloader, cert *x509.Certificate) ([]*x509.Certificate, error) {
	issuerUrls, err := c.prepareUrls(cert.IssuingCertificateURL)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare issuer URLs: %w", err)
	}

	issuers := make([]*x509.Certificate, len(issuerUrls))
	for idx, url := range issuerUrls {
		ctx, cancel := context.WithTimeout(context.Background(), downloader.timeout)
		defer cancel()

		cert, err := downloader.downloadCRLSigner(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("failed to download issuer certificate: %w", err)
		}
		issuers[idx] = cert
	}
	return issuers, nil
}

// filterIntermediates filters a pool of certificates to only return intermediate CA certificates.
func filterIntermediates(pool []*x509.Certificate) []*x509.Certificate {
	return sliceutil.Filter(pool, func(cert *x509.Certificate) (s *x509.Certificate, include bool) {
		if !cert.IsCA {
			return cert, false
		}

		if isSelfSigned(cert) {
			return cert, false
		}

		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return cert, false
		}

		return cert, true
	})
}

// isSelfSigned checks if a certificate is self-signed
func isSelfSigned(cert *x509.Certificate) bool {
	if !slices.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}

	return cert.CheckSignatureFrom(cert) == nil
}
