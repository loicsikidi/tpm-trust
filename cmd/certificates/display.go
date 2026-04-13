package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	internalcertinfo "github.com/loicsikidi/tpm-trust/internal/certinfo"
	"github.com/smallstep/certinfo"
)

func displayCertsPEM(certs []*x509.Certificate) error {
	for i, cert := range certs {
		if err := pem.Encode(os.Stdout, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return fmt.Errorf("failed to encode certificate %d: %w", i, err)
		}
	}
	return nil
}

func displayCertsText(certs []*x509.Certificate, short bool) error {
	for i, cert := range certs {
		if err := displayCertText(cert, short); err != nil {
			return fmt.Errorf("failed to format certificate %d: %w", i, err)
		}
		if i < len(certs)-1 {
			fmt.Println()
		}
	}
	return nil
}

func displayCertText(cert *x509.Certificate, short bool) error {
	var certText string
	var err error

	if short {
		certText, err = internalcertinfo.CertificateTextShort(cert)
	} else {
		certText, err = certinfo.CertificateText(cert)
	}

	if err != nil {
		return err
	}

	fmt.Println(certText)
	return nil
}
