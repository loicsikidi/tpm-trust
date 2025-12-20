package audit

import (
	"context"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/caarlos0/log"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
	"github.com/loicsikidi/tpm-trust/internal"
	"github.com/loicsikidi/tpm-trust/internal/logutil"
	"github.com/loicsikidi/tpm-trust/internal/privilege"
	"github.com/loicsikidi/tpm-trust/internal/tpm"
	"github.com/loicsikidi/tpm-trust/internal/validate"
	"github.com/spf13/cobra"
)

type options struct {
	skipRevocationCheck bool
	verbose             bool
}

func NewCommand() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "audit TPM's EK certificate against trusted manufacturers roots CAs",
		Long: `Ensure that a TPM is legitimate by verifying its Endorsement Key (EK)
certificate against a trust bundle of known TPM manufacturers.

Exit codes:
  0 - TPM is trusted
  1 - TPM is not trusted or validation failed`,
		Example: `  # Audit the TPM
  tpm-trust audit
  
  ## Audit without revocation check
  tpm-trust audit --skip-revocation-check

  ## Audit with verbose logging
  tpm-trust audit --verbose`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), opts)
		},
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().BoolVar(&opts.skipRevocationCheck, "skip-revocation-check", false, "Skip CRL revocation check")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "Enable verbose logging")

	return cmd
}

func run(ctx context.Context, opts *options) error {
	logger := log.New(os.Stdout)
	if opts.verbose {
		logger.Level = log.DebugLevel
	}

	if err := privilege.Elevate(); err != nil {
		return fmt.Errorf("failed to elevate privileges: %w", err)
	}

	startRead := time.Now()
	logger.Info("Reading EK certificate from TPM")
	result, err := tpm.GetEKCertificate(tpm.TPMConfig{Logger: logger})
	if err != nil {
		return fmt.Errorf("failed to read EK certificate: %w", err)
	}
	logutil.LogDuration(logger, startRead)

	startLoad := time.Now()
	cfg := apiv1beta.GetConfig{
		AutoUpdate: apiv1beta.AutoUpdateConfig{
			DisableAutoUpdate: true,
		},
	}
	trustedBundle, err := apiv1beta.GetTrustedBundle(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to get trusted bundle: %w", err)
	}
	logger.Info("Loading manufacturers trusted bundle")

	if !slices.Contains(trustedBundle.GetVendors(), apiv1beta.VendorID(result.Manufacturer.ASCII)) {
		logger.WithField("id", result.Manufacturer.ASCII).
			WithField("reason", `unfortunately, this manufacturer
is not included yet in 'tpm-ca-certificates' 🥹
Please open an issue to request its inclusion:
https://github.com/loicsikidi/tpm-ca-certificates/issues/new
`).
			Error("unsupported manufacturer")
		return internal.ErrSilence
	}

	logger.IncreasePadding()
	logger.WithField("id", result.Manufacturer.ASCII).Info("manufacturer supported")
	logger.DecreasePadding()
	logutil.LogDuration(logger, startLoad)

	startValidate := time.Now()
	logger.Info("Validating EK certificate")
	checker, err := validate.NewEKChecker(validate.EKCheckerConfig{
		TrustedBundle: trustedBundle,
		Logger:        logger,
	})
	if err != nil {
		return fmt.Errorf("failed to create EK checker: %w", err)
	}

	checkCfg := validate.CheckConfig{
		EK:                  result.Certificate,
		SkipRevocationCheck: opts.skipRevocationCheck,
	}
	if err := checker.Check(checkCfg); err != nil {
		return internal.ErrSilence
	}
	logutil.LogDuration(logger, startValidate)

	logger.Info("TPM is genuine 🔒")
	return nil
}
