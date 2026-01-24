package tpm

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func Test_findKeyType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		public tpm2.TPMTPublic
		want   KeyType
	}{
		{
			name: "rsa-2048",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{KeyBits: 2048},
				),
			},
			want: KeyTypeRSA2048,
		},
		{
			name: "rsa-3072",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{KeyBits: 3072},
				),
			},
			want: KeyTypeRSA3072,
		},
		{
			name: "rsa-4096",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{KeyBits: 4096},
				),
			},
			want: KeyTypeRSA4096,
		},
		{
			name: "ecc-nist-p256",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{CurveID: tpm2.TPMECCNistP256},
				),
			},
			want: KeyTypeECCNistP256,
		},
		{
			name: "ecc-nist-p384",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{CurveID: tpm2.TPMECCNistP384},
				),
			},
			want: KeyTypeECCNistP384,
		},
		{
			name: "ecc-nist-p521",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{CurveID: tpm2.TPMECCNistP521},
				),
			},
			want: KeyTypeECCNistP521,
		},
		{
			name: "ecc-sm2-p256",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{CurveID: tpm2.TPMECCSM2P256},
				),
			},
			want: KeyTypeECCSM2P256,
		},
		{
			name: "unknown algorithm",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgKeyedHash,
			},
			want: KeyTypeUnknown,
		},
		{
			name: "unknown ecc curve",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{CurveID: tpm2.TPMECCBNP256},
				),
			},
			want: KeyTypeUnknown,
		},
		{
			name: "non-standard rsa key size",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{KeyBits: 1024},
				),
			},
			want: KeyType("rsa-1024"),
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := findKeyType(tc.public)
			if got != tc.want {
				t.Errorf("findKeyType() = %v, want %v", got, tc.want)
			}
		})
	}
}
