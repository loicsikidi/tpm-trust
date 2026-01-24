package certificates

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/loicsikidi/attest/info"
	"github.com/loicsikidi/tpm-trust/internal/privilege"
	"github.com/loicsikidi/tpm-trust/internal/tpm"
	"github.com/spf13/cobra"

	"github.com/loicsikidi/tpm-trust/internal/log"
)

type listOptions struct {
	verbose bool
	format  string
}

// Check validates the listOptions configuration.
func (o *listOptions) Check() error {
	if o.format != "text" && o.format != "json" {
		return fmt.Errorf("invalid format: %s (must be 'text' or 'json')", o.format)
	}
	return nil
}

func newListCommand() *cobra.Command {
	opts := &listOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "list available TPM EK certificates",
		Long: `List all Endorsement Key (EK) certificates available in the TPM.
For each certificate, displays:
  - Key type (kty): algorithm and size (e.g., rsa-2048, ecc-nist-p256)
  - Issuer: certificate issuer
  - Subject: certificate subject`,
		Example: `  # List all available EK certificates
  tpm-trust certificates list

  # List with verbose logging
  tpm-trust certificates list --verbose

  # List in JSON format
  tpm-trust certificates list --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(cmd.Context(), opts)
		},
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "Enable verbose logging")
	cmd.Flags().StringVar(&opts.format, "format", "text", "Output format: text or json")

	return cmd
}

func runList(_ context.Context, opts *listOptions) error {
	if err := opts.Check(); err != nil {
		return err
	}

	if err := privilege.Elevate(); err != nil {
		return fmt.Errorf("failed to elevate privileges: %w", err)
	}

	var logger log.Logger
	if opts.format == "json" {
		// Use noop logger for JSON output to avoid polluting the output
		logger = log.New(log.WithNoop())
	} else {
		logger = log.New(log.WithVerbose(opts.verbose))
	}

	logger.Info("Reading EK certificates from TPM")

	result, err := tpm.GetEKCertificates(tpm.TPMConfig{Logger: logger})
	if err != nil {
		return fmt.Errorf("failed to read EK certificates: %w", err)
	}

	if opts.format == "json" {
		return displayListJSON(result)
	}

	return displayListText(logger, result)
}

type certificateJSON struct {
	KeyType string          `json:"kty"`
	Issuer  string          `json:"issuer"`
	Subject string          `json:"subject,omitempty"`
	Chain   info.CertBundle `json:"chain,omitempty"`
}

type outputJSON struct {
	Certificates []certificateJSON `json:"certificates"`
}

func displayListJSON(result *tpm.EKCertsResponse) error {
	output := outputJSON{
		Certificates: make([]certificateJSON, 0, len(result.EKs)),
	}

	for _, ekInfo := range result.EKs {
		cert := ekInfo.EK.Certificate
		output.Certificates = append(output.Certificates, certificateJSON{
			KeyType: string(ekInfo.KeyType),
			Issuer:  cert.Issuer.String(),
			Subject: cert.Subject.String(),
			Chain:   ekInfo.EK.Chain,
		})
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func displayListText(logger log.Logger, result *tpm.EKCertsResponse) error {
	logger.Info("Available EK certificates:")
	logger.IncreasePadding()
	for i, ekInfo := range result.EKs {
		cert := ekInfo.EK.Certificate
		logger.Infof("Certificate %d:", i+1)
		logger.IncreasePadding()
		logger.WithField("kty", string(ekInfo.KeyType)).Info("key type")
		logger.WithField("issuer", cert.Issuer.String()).Info("issuer")
		if cert.Subject.String() != "" {
			logger.WithField("subject", cert.Subject.String()).Info("subject")
		}
		if len(ekInfo.EK.Chain) > 0 {
			for _, cert := range ekInfo.EK.Chain {
				logger.
					WithField("issuer", cert.Issuer.String()).
					WithField("subject", cert.Subject.String()).
					Info("intermediate")
			}
		}
		logger.DecreasePadding()
	}
	logger.DecreasePadding()

	return nil
}
