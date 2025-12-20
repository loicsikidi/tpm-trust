package tpm

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/caarlos0/log"
	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/attest"
	"github.com/loicsikidi/attest/endorsement"
	"github.com/loicsikidi/attest/info"
)

type TPMConfig struct {
	Logger *log.Logger
}

func (c *TPMConfig) CheckAndSetDefaults() error {
	return nil
}

type EKResponse struct {
	Certificate  *x509.Certificate
	Manufacturer info.Manufacturer
}

// GetEKCertificate retrieves the Endorsement Key (EK) certificate from the TPM.
// It opens the TPM device, reads the EK certificate, and returns it as an x509.Certificate.
func GetEKCertificate(cfg TPMConfig) (*EKResponse, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	logger := cfg.Logger
	logger.IncreasePadding()
	defer logger.ResetPadding()

	logger.Debug("open connection to TPM")
	tpm, err := attest.OpenTPM(nil)
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
	logger.WithField("id", info.Manufacturer.ASCII).Infof("manufacturer: %s", info.Manufacturer.Name)

	ek, err := search(logger, tpm)
	if err != nil {
		return nil, err
	}
	return &EKResponse{Certificate: ek.Certificate, Manufacturer: info.Manufacturer}, nil
}

// search looks for an Endorsement Key (EK) certificate in the NVRAM of the TPM.
func search(logger *log.Logger, tpm *attest.TPM) (endorsement.EK, error) {
	// Objective: be the fastest possible because the app is user visible.
	// In order to achieve that, we:
	// 1. Search available EK certs in TPM (using nv indices)
	// 2. Try to use persisted EK handles if any
	// 3. Fallback to generating new EK key
	//   3.a Try ECC first (faster key generation)
	//   3.b Fallback to RSA if ECC is not available
	logger.Info("start searching for EK certificates")
	availableCerts := endorsement.SearchAvailableCertificates(tpm.Tpm())
	// TODO(lsikidi): support EKCertURL (i.e. AMD, INTC) scenario
	if len(availableCerts) == 0 {
		return endorsement.EK{}, fmt.Errorf("no EK certificates available in TPM")
	}
	logger.Infof("found %d EK certificate(s)", len(availableCerts))
	logger.IncreasePadding()
	for _, t := range availableCerts {
		logger.WithField("kty", findKeyType(t.Public)).
			Info("certificate")
	}
	logger.DecreasePadding()

	templates := tpm.PersistedEKs()
	var (
		ek     endorsement.EK
		errGet error
	)
	switch {
	case len(templates) >= 1:
		logger.Debugf("found %d persisted handle(s)", len(templates))
		ek, errGet = tpm.EK(attest.GetEKCertConfig{Template: templates[0]})
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
		Infof("select %s EK certificate", findKeyType(*ek.Public))
	return ek, nil
}

// findKeyType determines the key type from a [tpm2.TPMTPublic].
// It returns a string describing the key algorithm and size (e.g., "rsa2048", "ecc-nist-p256").
// Returns "unknown" for unsupported key types.
func findKeyType(public tpm2.TPMTPublic) string {
	switch {
	case public.Type == tpm2.TPMAlgRSA:
		rsaDetails, _ := public.Parameters.RSADetail()
		return fmt.Sprintf("rsa%d", rsaDetails.KeyBits)
	case public.Type == tpm2.TPMAlgECC:
		eccDetails, _ := public.Parameters.ECCDetail()
		var curveName string
		switch eccDetails.CurveID {
		case tpm2.TPMECCSM2P256:
			curveName = "sm2-p256"
		case tpm2.TPMECCNistP256:
			curveName = "nist-p256"
		case tpm2.TPMECCNistP384:
			curveName = "nist-p384"
		case tpm2.TPMECCNistP521:
			curveName = "nist-p521"
		default:
			curveName = "unknown"
		}
		return fmt.Sprintf("ecc-%s", curveName)
	default:
		return "unknown"
	}
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
