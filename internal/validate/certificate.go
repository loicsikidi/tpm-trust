package validate

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/loicsikidi/attest/endorsement"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
	"github.com/loicsikidi/tpm-trust/internal/log"
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
	logger     log.Logger
}

type EKCheckerConfig struct {
	Downloader    *downloader
	TrustedBundle apiv1beta.TrustedBundle
	Timeout       time.Duration
	Logger        log.Logger
}

func (e *EKCheckerConfig) CheckAndSetDefaults() error {
	if e.Logger == nil {
		e.Logger = log.New(log.WithNoop())
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
	EK                  endorsement.EK
	SkipRevocationCheck bool
}

func (c *CheckConfig) CheckAndSetDefaults() error {
	if c.EK.Certificate == nil {
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

	var issuers []*x509.Certificate
	if len(cfg.EK.Chain) > 0 {
		issuers = cfg.EK.Chain
		lastIdx := len(issuers) - 1
		parent, err := c.getIssuerCertificates(issuers[lastIdx])
		if err != nil {
			return nil
		}
		issuers = append(issuers, parent...)
	} else {
		var err error
		issuers, err = c.getIssuerCertificates(cfg.EK.Certificate)
		if err != nil {
			return err
		}
	}

	if !cfg.SkipRevocationCheck {
		crlUrls, err := c.prepareUrls(cfg.EK.Certificate.CRLDistributionPoints)
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

			if crl.IsRevoked(cfg.EK.Certificate) {
				return ErrCertificateRevoked
			}
		}
	}

	// Try verification with extended intermediates pool
	if err := c.verifyCertificateWithIssuers(cfg.EK.Certificate, issuers); err != nil {
		c.logger.WithError(err).Debug("certificate verification error")
		return fmt.Errorf("%w: %v", ErrUntrustedCertificate, err)
	}
	return nil
}

func (c *ekchecker) check(cfg *CheckConfig) error {
	switch {
	case cfg.EK.Certificate.IsCA:
		return ErrEKCannotBeCA
	// an arbitrary limit, so that we don't start making a large number of HTTP requests (if needed)
	case len(cfg.EK.Certificate.IssuingCertificateURL) > c.downloader.maxDownloads:
		return fmt.Errorf("number of Issuers (%d) bigger than the maximum allowed number (%d) of downloads", len(cfg.EK.Certificate.CRLDistributionPoints), c.downloader.maxDownloads)
	case !cfg.SkipRevocationCheck && len(cfg.EK.Certificate.CRLDistributionPoints) > c.downloader.maxDownloads:
		return fmt.Errorf("number of CRLs (%d) bigger than the maximum allowed number (%d) of downloads", len(cfg.EK.Certificate.CRLDistributionPoints), c.downloader.maxDownloads)
	}
	if len(cfg.EK.Certificate.CRLDistributionPoints) == 0 {
		c.logger.WithField("outcome", "revocation check will be skipped").Warn("missing CRL DP")
		cfg.SkipRevocationCheck = true
	}
	if len(cfg.EK.Certificate.UnhandledCriticalExtensions) > 0 {
		c.logger.WithField("extensions", cfg.EK.Certificate.UnhandledCriticalExtensions).
			Debug("found: unhandled critical extensions")
	}
	found := false
	for _, ext := range cfg.EK.Certificate.UnknownExtKeyUsage {
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
	seen := make(map[string]bool)

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

		// skip duplicate URLs
		urlStr := parsedURL.String()
		if seen[urlStr] {
			c.logger.WithField("endpoint", urlStr).
				Debug("skipping duplicate URL")
			continue
		}
		seen[urlStr] = true

		crlURLs = append(crlURLs, parsedURL)
	}
	return crlURLs, nil
}

// getIssuerCertificates retrieves the issuer certificates for the EK certificates.
// it's a strict function that expects to get all the issuer certificates
//
// TODO(lsikidi): support recursive issuer fetching for deeper chains
func (c *ekchecker) getIssuerCertificates(cert *x509.Certificate) ([]*x509.Certificate, error) {
	issuerUrls, err := c.prepareUrls(cert.IssuingCertificateURL)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare issuer URLs: %w", err)
	}

	var issuers []*x509.Certificate
	seen := make(map[string]bool)

	for _, url := range issuerUrls {
		ctx, cancel := context.WithTimeout(context.Background(), c.downloader.timeout)
		defer cancel()

		cert, err := c.downloader.downloadCRLSigner(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("failed to download issuer certificate: %w", err)
		}

		hash := sha256.Sum256(cert.Raw)
		fingerprint := hex.EncodeToString(hash[:])
		if seen[fingerprint] {
			c.logger.WithField("subject", cert.Subject.String()).
				WithField("endpoint", url.String()).
				WithField("fingerprint", fingerprint).
				Debug("skipping duplicate certificate")
			continue
		}
		seen[fingerprint] = true

		issuers = append(issuers, cert)
	}
	return issuers, nil
}

func (c *ekchecker) verifyCertificateWithIssuers(cert *x509.Certificate, issuers []*x509.Certificate) error {
	// Get base verify options from trusted bundle
	opts := c.tb.GetVerifyOptions()

	// Check which issuers are missing and add them to the intermediates pool
	certs := slices.Clone(issuers)

	for _, issuer := range certs {
		if !c.tb.Contains(issuer) {
			if isSelfSigned(issuer) {
				c.logger.WithField("subject", issuer.Subject.String()).
					WithField("reason", `unfortunately, the root certificate
is not included yet in 'tpm-ca-certificates' 🥹
Please open an issue to request its inclusion:
https://github.com/loicsikidi/tpm-ca-certificates/issues/new
`).
					Error("unsupported root certificate")
				continue
			}
			c.logger.WithField("reason", `the certificate is not included in the trusted bundle`).
				Infof("adding %q to verification pool", issuer.Subject.String())
			opts.Intermediates.AddCert(issuer)
		}
	}

	// Copy the EK certificate and mark all critical extensions as handled
	// to work around TPM-specific OIDs that x509 doesn't recognize
	certCopy := *cert
	certCopy.UnhandledCriticalExtensions = nil

	_, err := certCopy.Verify(opts)
	return err
}

// isSelfSigned checks if a certificate is self-signed
func isSelfSigned(cert *x509.Certificate) bool {
	if !slices.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}

	return cert.CheckSignatureFrom(cert) == nil
}
