package certificates

import (
	"context"
	"fmt"

	"github.com/loicsikidi/tpm-trust/internal/log"
	"github.com/loicsikidi/tpm-trust/internal/privilege"
	"github.com/loicsikidi/tpm-trust/internal/tpm"
	"github.com/spf13/cobra"
)

type bundleOptions struct {
	verbose bool
	short   bool
	format  string
}

func (o *bundleOptions) Check() error {
	if o.format != "text" && o.format != "pem" {
		return fmt.Errorf("invalid format: %s (must be 'text' or 'pem')", o.format)
	}
	return nil
}

func newBundleCommand() *cobra.Command {
	opts := &bundleOptions{}

	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "display EK certificate chains from TPM NVRAM",
		Long: `Display EK certificate chains stored in TPM NVRAM.

According to TCG TPM v2.0 Provisioning Guidance section 2.2.1.5.2,
EK certificate chains may be stored in NV indices 0x01c00100 through 0x01c001ff.`,
		Example: `  # Display EK certificate chains
  tpm-trust certificates bundle

  # Display in short format
  tpm-trust certificates bundle --short

  # Display in PEM format
  tpm-trust certificates bundle --format pem`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBundle(cmd.Context(), opts)
		},
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().BoolVar(&opts.short, "short", false, "Display short certificate information")
	cmd.Flags().StringVar(&opts.format, "format", "text", "Output format: text or pem")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "Enable verbose logging")

	return cmd
}

func runBundle(_ context.Context, opts *bundleOptions) error {
	if err := opts.Check(); err != nil {
		return err
	}

	if err := privilege.Elevate(); err != nil {
		return fmt.Errorf("failed to elevate privileges: %w", err)
	}

	var logger log.Logger
	if opts.verbose && opts.format != "pem" {
		logger = log.New(log.WithVerbose(opts.verbose))
	} else {
		logger = log.New(log.WithNoop())
	}

	logger.Info("Reading EK certificate chains from TPM NVRAM")

	tpmInfo, err := tpm.Info(tpm.TPMConfig{
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("failed to get TPM info: %w", err)
	}

	if !tpmInfo.HasEKCertChains() {
		return fmt.Errorf("no EK certificate chains found in TPM NVRAM")
	}

	if opts.format == "pem" {
		return displayCertsPEM(tpmInfo.EKCertChains)
	}

	return displayCertsText(tpmInfo.EKCertChains, opts.short)
}
