package crl

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"time"
)

var (
	ErrCrlIsExpired          = errors.New("CRL is expired")
	ErrCrlNotYetValid        = errors.New("CRL is not yet valid")
	ErrUnknownAuthorityError = errors.New("CRL signed by unknown authority")
	ErrCrlCannotBeNil        = errors.New("CRL cannot be nil")
)

type CRL interface {
	IsValid() error
	Verify(certs ...*x509.Certificate) error
	IsRevoked(cert *x509.Certificate) bool
}

type crl struct {
	*x509.RevocationList
}

func NewCRL(rl *x509.RevocationList) (CRL, error) {
	if rl == nil {
		return nil, ErrCrlCannotBeNil
	}

	c := &crl{RevocationList: rl}

	if err := c.IsValid(); err != nil {
		return nil, err
	}

	return c, nil
}

func Must(rl *x509.RevocationList) CRL {
	c, err := NewCRL(rl)
	if err != nil {
		panic(err)
	}
	return c
}

func (c *crl) IsValid() error {
	now := time.Now()

	if now.After(c.NextUpdate) {
		return ErrCrlIsExpired
	}
	if now.Before(c.ThisUpdate) {
		return ErrCrlNotYetValid
	}
	return nil
}

func (c *crl) Verify(certs ...*x509.Certificate) error {
	for _, cert := range certs {
		if err := c.CheckSignatureFrom(cert); err == nil {
			return nil
		}
	}
	return ErrUnknownAuthorityError
}

func (c *crl) IsRevoked(cert *x509.Certificate) bool {
	for _, entry := range c.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

func MarshalCRL(template *x509.RevocationList, issuer *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	return x509.CreateRevocationList(rand.Reader, template, issuer, signer)
}
