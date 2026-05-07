package validate

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/loicsikidi/attest/endorsement"
	"github.com/loicsikidi/go-utils/crypto/x509util"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
	"github.com/loicsikidi/tpm-trust/internal/log"
)

var (
	ErrUntrustedCertificate = errors.New("EK certificate trust could not be established")
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

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type ekchecker struct {
	verifier *x509util.CertVerifier
	tb       apiv1beta.TrustedBundle
	logger   log.Logger
	timeout  time.Duration
}

type EKCheckerConfig struct {
	TrustedBundle apiv1beta.TrustedBundle
	HttpClient    httpClient
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
	if e.HttpClient == nil {
		e.HttpClient = http.DefaultClient
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
	return nil
}

func NewEKChecker(cfg EKCheckerConfig) (Checker, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	v, err := x509util.NewCertVerifier(x509util.VerifierConfig{
		HttpClient: cfg.HttpClient,
		AfterDownloadHook: func(url *url.URL, kind string) {
			cfg.Logger.
				WithField("url", url.String()).
				Infof("%s downloaded", kind)
		},
		Cache: cfg.TrustedBundle,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate verifier: %w", err)
	}

	return &ekchecker{
		verifier: v,
		tb:       cfg.TrustedBundle,
		logger:   cfg.Logger,
		timeout:  cfg.Timeout,
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

	v := c.verifier

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	issuers, err := v.GetFullChain(ctx, cfg.EK.Certificate, cfg.EK.Chain)
	if err != nil && !c.safeToContinue(cfg) {
		c.logger.WithError(err).Debug("failed to get full chain")
		return fmt.Errorf("failed to get full chain: %w", err)
	}

	if !cfg.SkipRevocationCheck {
		config := x509util.RevocationConfig{
			Chain:     issuers,
			FullChain: true,
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
		if err := v.Verify(ctx, cfg.EK.Certificate, config); err != nil {
			return err
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
	if cfg.EK.Certificate.IsCA {
		return ErrEKCannotBeCA
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

func (c *ekchecker) verifyCertificateWithIssuers(cert *x509.Certificate, issuers []*x509.Certificate) error {
	var missingIssuers []*x509.Certificate
	for _, issuer := range issuers {
		if !c.tb.Contains(issuer) {
			if x509util.IsRoot(issuer) {
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
			missingIssuers = append(missingIssuers, issuer)
		}
	}
	return c.tb.Verify(cert, missingIssuers)
}

func (c *ekchecker) safeToContinue(cfg CheckConfig) bool {
	if !cfg.SkipRevocationCheck {
		return false
	}

	candidate := cfg.EK.Certificate
	if len(cfg.EK.Chain) > 0 {
		lastIdx := len(cfg.EK.Chain) - 1
		candidate = cfg.EK.Chain[lastIdx]
	}

	// Check if the candidate's issuer is in the trusted bundle
	return c.tb.ContainsFunc(func(c *x509.Certificate) bool {
		return bytes.Equal(c.RawSubject, candidate.RawIssuer)
	})
}
