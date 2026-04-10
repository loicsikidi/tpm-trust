package tpm

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/attest"
	"github.com/loicsikidi/attest/endorsement"
	"github.com/loicsikidi/attest/info"

	"github.com/loicsikidi/tpm-trust/internal/log"
	"github.com/loicsikidi/tpm-trust/internal/logutil"
	"github.com/loicsikidi/tpm-trust/internal/util"
)

// httpClient is an interface for making HTTP requests, allowing test injection.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// KeyType represents the type of TPM key algorithm and curve.
type KeyType string

func (k KeyType) String() string {
	return string(k)
}

// Key type constants representing different EK key algorithms and curves.
const (
	KeyTypeRSA2048     KeyType = "rsa-2048"
	KeyTypeRSA3072     KeyType = "rsa-3072"
	KeyTypeRSA4096     KeyType = "rsa-4096"
	KeyTypeECCSM2P256  KeyType = "ecc-sm2-p256"
	KeyTypeECCNistP256 KeyType = "ecc-nist-p256"
	KeyTypeECCNistP384 KeyType = "ecc-nist-p384"
	KeyTypeECCNistP521 KeyType = "ecc-nist-p521"
	KeyTypeUnknown     KeyType = "unknown"
)

// validKeyTypes contains all supported key types for validation.
var validKeyTypes = []KeyType{
	KeyTypeRSA2048,
	KeyTypeRSA3072,
	KeyTypeRSA4096,
	KeyTypeECCSM2P256,
	KeyTypeECCNistP256,
	KeyTypeECCNistP384,
	KeyTypeECCNistP521,
}

type TPMConfig struct {
	Logger  log.Logger
	KeyType KeyType
	// If true, skip matching the public key during EK certificate search for faster operation
	SkipPublicMatching bool
}

func (c *TPMConfig) CheckAndSetDefaults() error {
	if c.Logger == nil {
		c.Logger = log.New(log.WithNoop())
	}

	if c.KeyType != "" {
		if !slices.Contains(validKeyTypes, c.KeyType) {
			validTypes := util.Map(validKeyTypes, func(kt KeyType) string { return kt.String() })
			return fmt.Errorf("invalid key type: %s (must be one of: %s)", c.KeyType, strings.Join(validTypes, ", "))
		}
	}

	return nil
}

type EKResponse struct {
	EK           endorsement.EK
	Manufacturer info.Manufacturer
}

// EKInfo contains information about an available EK certificate.
type EKInfo struct {
	KeyType KeyType
	EK      endorsement.EK
}

// EKCertsResponse contains all available EK certificates and manufacturer info.
type EKCertsResponse struct {
	EKs []EKInfo
}

// GetEKCertificates retrieves all available Endorsement Key (EK) certificates from the TPM.
// It opens the TPM device, searches for all available EK certificates, and returns them.
func GetEKCertificates(cfg TPMConfig) (*EKCertsResponse, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	logger := cfg.Logger
	logger.IncreasePadding()
	defer logger.DecreasePadding()

	logger.Debug("open connection to TPM")
	tpm, err := attest.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer func() {
		logger.Debug("closing connection to TPM")
		if closeErr := tpm.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close TPM: %w (original error: %v)", closeErr, err)
		}
	}()

	ekCerts, err := tpm.EKCertificates(endorsement.SearchCertConfig{
		SkipPublicMatching: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get EK certificates: %w", err)
	}
	logger.Debugf("found %d EK certificate(s)", len(ekCerts))

	var ekInfos []EKInfo
	for _, ek := range ekCerts {
		ekInfos = append(ekInfos, EKInfo{
			KeyType: findKeyTypeFromCert(ek.Certificate),
			EK:      ek,
		})
	}

	var resp *EKCertsResponse
	if len(ekInfos) > 0 {
		resp = &EKCertsResponse{
			EKs: ekInfos,
		}
	}

	return resp, nil
}

// SearchEKCertificate retrieves the Endorsement Key (EK) certificate from the TPM.
// It differs from [GetEKCertificates] because it will ensure:
//   - cert is bound to TPM (public key matches TPM key)
//   - search logic is blazingly fast
func SearchEKCertificate(cfg TPMConfig) (*EKResponse, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	logger := cfg.Logger
	logger.IncreasePadding()
	defer logger.DecreasePadding()

	logger.Debug("open connection to TPM")
	tpm, err := attest.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer func() {
		logger.Debug("closing connection to TPM")
		if closeErr := tpm.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close TPM: %w (original error: %v)", closeErr, err)
		}
	}()

	logger.Debug("getting TPM info")
	info, err := tpm.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM info: %w", err)
	}
	logger.WithField("id", info.Manufacturer.ASCII).Infof("manufacturer: %q", info.Manufacturer.Name)

	ek, err := search(logger, tpm, info)
	if err != nil {
		return nil, err
	}
	return &EKResponse{EK: ek, Manufacturer: info.Manufacturer}, nil
}

// search looks for an Endorsement Key (EK) certificate in the NVRAM of the TPM.
// If no certificates are found in NV, it falls back to fetching from the
// manufacturer's EK certificate URL (supported for AMD and Intel).
func search(logger log.Logger, tpm *attest.TPM, tpmInfo *info.TPMInfo) (endorsement.EK, error) {
	// Objective: be the fastest possible because the app is user visible.
	// In order to achieve that, we:
	// 1. Search available EK certs in TPM (using nv indices)
	// 2. Try to use persisted EK handles if any
	// 3. Fallback to generating new EK key
	//   3.a Try ECC first (faster key generation)
	//   3.b Fallback to RSA if ECC is not available
	logger.Info("start searching for EK certificates")
	availableCerts := endorsement.SearchAvailableCertificates(tpm.Tpm())
	if len(availableCerts) == 0 {
		logger.Debug("no EK certificates found in NV, falling back to manufacturer EK cert URL")
		return fetchEKCertFromURL(logger, tpm, tpmInfo)
	}
	logger.Infof("found %d EK certificate(s):", len(availableCerts))
	logutil.LogWithPadding(logger, func() {
		for _, t := range availableCerts {
			logger.WithField("kty", findKeyType(t.Public)).
				Info("certificate")
		}
	})

	templates := tpm.PersistedEKs()
	var (
		ek     endorsement.EK
		errGet error
	)
	switch {
	case len(templates) >= 1:
		logger.Debugf("found %d persisted handle(s):", len(templates))
		logutil.LogWithPadding(logger, func() {
			for _, t := range templates {
				logger.WithField("index", fmt.Sprintf("0x%X", t.Index)).
					Debug("handle")
			}
		})
		ek, errGet = tpm.EK(attest.GetEKCertConfig{Template: templates[0]})
		if errGet != nil {
			return endorsement.EK{}, fmt.Errorf("failed to get EK from persisted handle: %w", errGet)
		}
	case len(templates) == 0:
		logger.Debug("no persisted handles found")
		logger.Debug("must generate associated EK key pair in TPM")

		// let's try get ECC cert first because key generation is faster
		ek, errGet = getEK(tpm, tpm2.TPMAlgECC, availableCerts)
		if errGet == nil {
			logger.Debug("found ECC certificate")
			break
		}
		if errors.Is(errGet, attest.ErrEKCertNotFound) {
			logger.Debug("no ECC certificate found, trying RSA")
			logger.WithField("reason", `for security reasons, the key pair associated
with the certificate is regenerated in the TPM
to ensure proper binding. Unfortunately, RSA key
generation is computationally expensive.`).
				Warn("can take a bit of time...")
			ek, errGet = getEK(tpm, tpm2.TPMAlgRSA, availableCerts)
			if errGet != nil {
				return endorsement.EK{}, fmt.Errorf("failed to get any EK cert: %w", errGet)
			}
			logger.Debug("found RSA certificate")
		}
		return endorsement.EK{}, fmt.Errorf("failed to get EK ECC cert: %w", errGet)
	}
	logger.WithField("issuer", ek.Certificate.Issuer).
		Infof("select %s certificate", findKeyTypeFromCert(ek.Certificate))
	return ek, nil
}

func getEK(tpm *attest.TPM, alg tpm2.TPMAlgID, availableCerts []attest.EKCertTemplate) (endorsement.EK, error) {
	if slices.ContainsFunc(availableCerts, func(t attest.EKCertTemplate) bool {
		return t.Type() == alg
	}) {
		var template attest.EKCertTemplate
		for _, t := range availableCerts {
			if t.Type() == alg {
				template = t
				break
			}
		}
		return tpm.EK(attest.GetEKCertConfig{Template: template})
	}
	return endorsement.EK{}, attest.ErrEKCertNotFound
}

// fetchEKCertFromURL generates an EK public key and fetches the EK certificate
// from the manufacturer's URL (supported for AMD and Intel fTPMs where the
// certificate is not pre-provisioned in TPM NV storage).
// It tries RSA first, then ECC, as both key types may have a URL.
func fetchEKCertFromURL(logger log.Logger, tpm *attest.TPM, tpmInfo *info.TPMInfo) (endorsement.EK, error) {
	return fetchEKCertFromURLWithClient(logger, tpm, tpmInfo, http.DefaultClient)
}

// fetchEKCertFromURLWithClient is the internal implementation with an injectable HTTP client.
func fetchEKCertFromURLWithClient(logger log.Logger, tpm *attest.TPM, tpmInfo *info.TPMInfo, client httpClient) (endorsement.EK, error) {
	// Try ECC first (faster key generation), then RSA. AMD and Intel compute cert URLs for both key types.
	for _, tmpl := range []endorsement.Template{endorsement.TemplateECC, endorsement.TemplateRSA} {
		ek, err := endorsement.Get(tpm.Tpm(), endorsement.GetConfig{
			Template: tmpl,
			Info:     *tpmInfo,
		})
		if err != nil || ek.CertificateURL == "" {
			continue
		}

		logger.WithField("url", ek.CertificateURL).Debug("fetching EK certificate from manufacturer URL")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cert, err := fetchCertFromURL(ctx, ek.CertificateURL, client)
		if err != nil {
			return endorsement.EK{}, err
		}

		ek.Certificate = cert
		logger.WithField("issuer", cert.Issuer).
			Infof("select %s certificate (via URL)", findKeyTypeFromCert(cert))
		return ek, nil
	}

	return endorsement.EK{}, fmt.Errorf("no EK certificates available in TPM and manufacturer %q does not support URL-based cert retrieval", tpmInfo.Manufacturer.ASCII)
}

// fetchCertFromURL fetches a DER-encoded EK certificate from the given URL.
func fetchCertFromURL(ctx context.Context, certURL string, client httpClient) (*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request for EK cert URL: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EK certificate from %s: %w", certURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP %d fetching EK certificate from %s", resp.StatusCode, certURL)
	}

	certData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read EK certificate response: %w", err)
	}

	cert, err := endorsement.ParseEKCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EK certificate from URL: %w", err)
	}

	return cert, nil
}

// GetEKCertificate retrieves a specific Endorsement Key (EK) certificate by key type.
// This function doesn't perform any security checks.
func GetEKCertificate(cfg TPMConfig) (*EKResponse, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	logger := cfg.Logger
	logger.IncreasePadding()
	defer logger.DecreasePadding()

	logger.Debug("open connection to TPM")
	tpm, err := attest.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer func() {
		logger.Debug("closing connection to TPM")
		if closeErr := tpm.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close TPM: %w (original error: %v)", closeErr, err)
		}
	}()

	logger.Debugf("searching for %s EK certificate", cfg.KeyType)
	availableCerts := endorsement.SearchAvailableCertificates(tpm.Tpm())
	if len(availableCerts) == 0 {
		return nil, fmt.Errorf("no EK certificates available in TPM")
	}

	var targetTemplate *attest.EKCertTemplate
	for _, certTemplate := range availableCerts {
		if findKeyType(certTemplate.Public) == cfg.KeyType {
			targetTemplate = &certTemplate
			break
		}
	}

	if targetTemplate == nil {
		return nil, fmt.Errorf("no EK certificate found for key type %s", cfg.KeyType)
	}

	ek, err := tpm.EK(attest.GetEKCertConfig{
		Template:           *targetTemplate,
		SkipPublicMatching: cfg.SkipPublicMatching,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get EK certificate: %w", err)
	}

	logger.Infof("found %s EK certificate", cfg.KeyType)

	info, err := tpm.Info()
	if err != nil {
		return nil, err
	}

	return &EKResponse{
		EK:           ek,
		Manufacturer: info.Manufacturer,
	}, nil
}

// findKeyType determines the key type from a [tpm2.TPMTPublic].
// It returns a [KeyType] describing the key algorithm and size (e.g., [KeyTypeRSA2048], [KeyTypeECCNistP256]).
// Returns [KeyTypeUnknown] for unsupported key types.
func findKeyType(public tpm2.TPMTPublic) KeyType {
	switch public.Type {
	case tpm2.TPMAlgRSA:
		rsaDetails, _ := public.Parameters.RSADetail()
		switch rsaDetails.KeyBits {
		case 2048:
			return KeyTypeRSA2048
		case 3072:
			return KeyTypeRSA3072
		case 4096:
			return KeyTypeRSA4096
		default:
			return KeyType(fmt.Sprintf("rsa-%d", rsaDetails.KeyBits))
		}
	case tpm2.TPMAlgECC:
		eccDetails, _ := public.Parameters.ECCDetail()
		switch eccDetails.CurveID {
		case tpm2.TPMECCSM2P256:
			return KeyTypeECCSM2P256
		case tpm2.TPMECCNistP256:
			return KeyTypeECCNistP256
		case tpm2.TPMECCNistP384:
			return KeyTypeECCNistP384
		case tpm2.TPMECCNistP521:
			return KeyTypeECCNistP521
		default:
			return KeyTypeUnknown
		}
	default:
		return KeyTypeUnknown
	}
}

// findKeyTypeFromCert determines the key type from an [x509.Certificate].
// It returns a [KeyType] describing the key algorithm and size (e.g., [KeyTypeRSA2048], [KeyTypeECCNistP256]).
// Returns [KeyTypeUnknown] for unsupported key types.
func findKeyTypeFromCert(cert *x509.Certificate) KeyType {
	if cert == nil || cert.PublicKey == nil {
		return KeyTypeUnknown
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keyBits := pub.N.BitLen()
		switch keyBits {
		case 2048:
			return KeyTypeRSA2048
		case 3072:
			return KeyTypeRSA3072
		case 4096:
			return KeyTypeRSA4096
		default:
			return KeyType(fmt.Sprintf("rsa-%d", keyBits))
		}
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().Name {
		case "sm2p256v1":
			return KeyTypeECCSM2P256
		case "P-256":
			return KeyTypeECCNistP256
		case "P-384":
			return KeyTypeECCNistP384
		case "P-521":
			return KeyTypeECCNistP521
		default:
			return KeyTypeUnknown
		}
	default:
		return KeyTypeUnknown
	}
}
