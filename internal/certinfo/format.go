package certinfo

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// CertificateTextShort formats an x509.Certificate in a custom certext
// format
//
// The output includes: certificate type, key algorithm, serial number,
// subject, SKI, issuer, AKI, AIA, CRLDP, and validity period.
func CertificateTextShort(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("certificate cannot be nil")
	}

	var b strings.Builder

	keyType := extractKeyType(cert)
	serial := formatSerial(cert.SerialNumber)
	fmt.Fprintf(&b, "X.509v3 TLS Certificate (%s) [Serial: %s]\n", keyType, serial)

	subject := cert.Subject.String()
	if subject == "" {
		b.WriteString("  Subject:\n")
	} else {
		fmt.Fprintf(&b, "  Subject:     %s\n", subject)
	}

	ski := formatHex(cert.SubjectKeyId)
	if ski == "" {
		b.WriteString("  SKI:\n")
	} else {
		fmt.Fprintf(&b, "  SKI:         %s\n", ski)
	}

	issuer := cert.Issuer.String()
	if issuer == "" {
		b.WriteString("  Issuer:\n")
	} else {
		fmt.Fprintf(&b, "  Issuer:      %s\n", issuer)
	}

	aki := formatHex(cert.AuthorityKeyId)
	if aki == "" {
		b.WriteString("  AKI:\n")
	} else {
		fmt.Fprintf(&b, "  AKI:         %s\n", aki)
	}

	writeField(&b, "AIA", cert.IssuingCertificateURL)
	writeField(&b, "CRLDP", cert.CRLDistributionPoints)

	fmt.Fprintf(&b, "  Valid from:  %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Fprintf(&b, "          to:  %s", cert.NotAfter.Format(time.RFC3339))

	return b.String(), nil
}

// extractKeyType determines the key type and size/curve from the certificate's public key.
// Returns a human-readable string like "RSA 2048" or "ECC NIST-P256".
func extractKeyType(cert *x509.Certificate) string {
	if cert == nil || cert.PublicKey == nil {
		return "UNKNOWN"
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		return fmt.Sprintf("RSA %d", bits)
	case *ecdsa.PublicKey:
		curveName := pub.Curve.Params().Name
		switch curveName {
		case "P-256":
			return "ECC NIST-P256"
		case "P-384":
			return "ECC NIST-P384"
		case "P-521":
			return "ECC NIST-P521"
		case "sm2p256v1":
			return "ECC SM2-P256"
		default:
			return fmt.Sprintf("ECC %s", curveName)
		}
	default:
		return "UNKNOWN"
	}
}

// formatSerial converts a serial number to a  string with truncation.
// For serials longer than 8 characters, it shows first4...last4.
func formatSerial(serial *big.Int) string {
	if serial == nil {
		return ""
	}

	str := serial.String()
	if len(str) <= 8 {
		return str
	}

	return fmt.Sprintf("%s...%s", str[:4], str[len(str)-4:])
}

// formatHex formats a byte array as colon-separated uppercase hex.
// Returns empty string for nil or empty input.
func formatHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var parts []string
	for _, b := range data {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(parts, ":")
}

// writeField writes a field with proper formatting for slice values.
func writeField(b *strings.Builder, name string, values []string) {
	switch len(values) {
	case 0:
		fmt.Fprintf(b, "  %s:\n", name)
	case 1:
		fmt.Fprintf(b, "  %-12s %s\n", name+":", values[0])
	default:
		fmt.Fprintf(b, "  %s:\n", name)
		for _, v := range values {
			fmt.Fprintf(b, "%15s%s\n", "", v)
		}
	}
}
