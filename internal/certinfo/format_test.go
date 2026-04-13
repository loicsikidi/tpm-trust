package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestFormatShort(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		wantType string
		wantErr  bool
	}{
		{
			name:    "nil certificate",
			cert:    nil,
			wantErr: true,
		},
		{
			name:     "RSA 2048 certificate",
			cert:     createRSACert(t, 2048),
			wantType: "RSA 2048",
		},
		{
			name:     "RSA 4096 certificate",
			cert:     createRSACert(t, 4096),
			wantType: "RSA 4096",
		},
		{
			name:     "ECC P-256 certificate",
			cert:     createECCCert(t, elliptic.P256()),
			wantType: "ECC NIST-P256",
		},
		{
			name:     "ECC P-384 certificate",
			cert:     createECCCert(t, elliptic.P384()),
			wantType: "ECC NIST-P384",
		},
		{
			name:     "certificate with all fields",
			cert:     createFullCert(t),
			wantType: "RSA 2048",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CertificateTextShort(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormatShort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Check that output contains expected key type
			if !strings.Contains(got, tt.wantType) {
				t.Errorf("FormatShort() output missing key type %q, got:\n%s", tt.wantType, got)
			}

			// Check that output contains required fields
			requiredFields := []string{
				"X.509v3 TLS Certificate",
				"Subject:",
				"SKI:",
				"Issuer:",
				"AKI:",
				"AIA:",
				"CRLDP:",
				"Valid from:",
				"to:",
			}
			for _, field := range requiredFields {
				if !strings.Contains(got, field) {
					t.Errorf("FormatShort() output missing field %q, got:\n%s", field, got)
				}
			}
		})
	}
}

func TestFormatSerial(t *testing.T) {
	tests := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{
			name:   "nil serial",
			serial: nil,
			want:   "",
		},
		{
			name:   "short serial",
			serial: big.NewInt(0x1234),
			want:   "4660",
		},
		{
			name:   "8 char serial",
			serial: big.NewInt(0x12345678),
			want:   "3054...9896",
		},
		{
			name:   "long serial gets truncated",
			serial: new(big.Int).SetBytes([]byte{0x93, 0x37, 0x11, 0x22, 0x33, 0x44, 0x78, 0x27}),
			want:   "1060...8151",
		},
		{
			name:   "very long serial",
			serial: new(big.Int).SetBytes([]byte{0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x00, 0xFF}),
			want:   "8113...8175",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatSerial(tt.serial); got != tt.want {
				t.Errorf("formatSerial() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatHex(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "nil data",
			data: nil,
			want: "",
		},
		{
			name: "empty data",
			data: []byte{},
			want: "",
		},
		{
			name: "single byte",
			data: []byte{0x42},
			want: "42",
		},
		{
			name: "multiple bytes",
			data: []byte{0x72, 0xB0, 0x3D, 0x71},
			want: "72:B0:3D:71",
		},
		{
			name: "full SKI example",
			data: []byte{0x72, 0xB0, 0x3D, 0x71, 0x22, 0x81, 0x95, 0x34, 0x63, 0xBC, 0x72, 0x60, 0x98, 0xEA, 0x3B, 0xC2, 0xF3, 0xB1, 0x3F, 0xA6},
			want: "72:B0:3D:71:22:81:95:34:63:BC:72:60:98:EA:3B:C2:F3:B1:3F:A6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatHex(tt.data); got != tt.want {
				t.Errorf("formatHex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractKeyType(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "nil certificate",
			cert: nil,
			want: "UNKNOWN",
		},
		{
			name: "RSA 2048",
			cert: createRSACert(t, 2048),
			want: "RSA 2048",
		},
		{
			name: "RSA 3072",
			cert: createRSACert(t, 3072),
			want: "RSA 3072",
		},
		{
			name: "RSA 4096",
			cert: createRSACert(t, 4096),
			want: "RSA 4096",
		},
		{
			name: "ECC P-256",
			cert: createECCCert(t, elliptic.P256()),
			want: "ECC NIST-P256",
		},
		{
			name: "ECC P-384",
			cert: createECCCert(t, elliptic.P384()),
			want: "ECC NIST-P384",
		},
		{
			name: "ECC P-521",
			cert: createECCCert(t, elliptic.P521()),
			want: "ECC NIST-P521",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractKeyType(tt.cert); got != tt.want {
				t.Errorf("extractKeyType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper functions to create test certificates

func createRSACert(t *testing.T, bits int) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	return &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "Test RSA Certificate",
		},
		Issuer: pkix.Name{
			CommonName: "Test Issuer",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		PublicKey: &key.PublicKey,
	}
}

func createECCCert(t *testing.T, curve elliptic.Curve) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECC key: %v", err)
	}

	return &x509.Certificate{
		SerialNumber: big.NewInt(67890),
		Subject: pkix.Name{
			CommonName: "Test ECC Certificate",
		},
		Issuer: pkix.Name{
			CommonName: "Test Issuer",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		PublicKey: &key.PublicKey,
	}
}

func createFullCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	return &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes([]byte{0x93, 0x37, 0x11, 0x22, 0x33, 0x44, 0x78, 0x27}),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test CA Org"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Date(2023, 5, 20, 6, 58, 48, 0, time.UTC),
		NotAfter:              time.Date(2043, 5, 16, 6, 58, 48, 0, time.UTC),
		SubjectKeyId:          []byte{0x72, 0xB0, 0x3D, 0x71, 0x22, 0x81, 0x95, 0x34},
		AuthorityKeyId:        []byte{0x72, 0xB0, 0x3D, 0x71, 0x22, 0x81, 0x95, 0x34, 0x63, 0xBC, 0x72, 0x60, 0x98, 0xEA, 0x3B, 0xC2, 0xF3, 0xB1, 0x3F, 0xA6},
		IssuingCertificateURL: []string{"https://example.com/ca.cer"},
		CRLDistributionPoints: []string{"https://example.com/crl"},
		PublicKey:             &key.PublicKey,
	}
}
