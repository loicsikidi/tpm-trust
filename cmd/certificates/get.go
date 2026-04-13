package certificates

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/loicsikidi/tpm-trust/internal/log"
	"github.com/loicsikidi/tpm-trust/internal/privilege"
	"github.com/loicsikidi/tpm-trust/internal/tpm"
	"github.com/spf13/cobra"
)

type getOptions struct {
	verbose bool
	short   bool
	format  string
	bundle  bool
}

// Check validates the getOptions configuration.
func (o *getOptions) Check() error {
	if o.format != "text" && o.format != "pem" {
		return fmt.Errorf("invalid format: %s (must be 'text' or 'pem')", o.format)
	}
	return nil
}

func newGetCommand() *cobra.Command {
	opts := &getOptions{}

	cmd := &cobra.Command{
		Use:   "get KTY",
		Short: "display a specific TPM EK certificate",
		Long: `Display a specific Endorsement Key (EK) certificate by key type.

Available key types (KTY):
  - rsa-2048, rsa-3072, rsa-4096
  - ecc-nist-p256, ecc-nist-p384, ecc-nist-p521
  - ecc-sm2-p256`,
		Example: `  # Display RSA 2048 EK certificate
  tpm-trust certificates get rsa-2048

  # Display certificate in short format
  tpm-trust certificates get ecc-nist-p256 --short

  # Display certificate in PEM format
  tpm-trust certificates get rsa-2048 --format pem

  # Display full certificate chain
  tpm-trust certificates get rsa-2048 --bundle`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(cmd.Context(), opts, args)
		},
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().BoolVar(&opts.short, "short", false, "Display short certificate information")
	cmd.Flags().StringVar(&opts.format, "format", "text", "Output format: text or pem")
	cmd.Flags().BoolVar(&opts.bundle, "bundle", false, "Display full certificate chain if available")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "Enable verbose logging")

	return cmd
}

func runGet(_ context.Context, opts *getOptions, args []string) error {
	if err := opts.Check(); err != nil {
		return err
	}

	keyType := tpm.KeyType(args[0])

	if err := privilege.Elevate(); err != nil {
		return fmt.Errorf("failed to elevate privileges: %w", err)
	}

	var logger log.Logger
	if opts.verbose && opts.format != "pem" {
		logger = log.New(log.WithVerbose(opts.verbose))
	} else {
		// Use noop logger for JSON output to avoid polluting the output
		logger = log.New(log.WithNoop())
	}

	logger.Infof("Reading %s EK certificate from TPM", keyType)

	result, err := tpm.GetEKCertificate(tpm.TPMConfig{
		Logger:  logger,
		KeyType: keyType,
		// "get" fn is not a critical, we can skip public matching for faster operation
		SkipPublicMatching: true,
	})
	if err != nil {
		return fmt.Errorf("failed to read EK certificate: %w", err)
	}

	if opts.format == "pem" {
		return displayPEM(result, opts.bundle)
	}

	return displayText(result, opts.short, opts.bundle)
}

func displayPEM(result *tpm.EKResponse, bundle bool) error {
	certs := []*x509.Certificate{result.EK.Certificate}
	if bundle && len(result.EK.Chain) > 0 {
		certs = append(certs, result.EK.Chain...)
	}
	return displayCertsPEM(certs)
}

func displayText(result *tpm.EKResponse, short bool, bundle bool) error {
	certs := []*x509.Certificate{result.EK.Certificate}
	if bundle && len(result.EK.Chain) > 0 {
		certs = append(certs, result.EK.Chain...)
	}
	return displayCertsText(certs, short)
}
