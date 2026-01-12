package audit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
	"github.com/loicsikidi/tpm-trust/internal"
	"github.com/loicsikidi/tpm-trust/internal/logutil"
	"github.com/loicsikidi/tpm-trust/internal/privilege"
	"github.com/loicsikidi/tpm-trust/internal/tpm"
	"github.com/loicsikidi/tpm-trust/internal/validate"
	"github.com/spf13/cobra"

	"github.com/loicsikidi/tpm-trust/internal/log"
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
	logger := log.New(log.WithVerbose(opts.verbose))

	if err := privilege.Elevate(); err != nil {
		return fmt.Errorf("failed to elevate privileges: %w", err)
	}

	startRead := time.Now()
	logger.Info("Reading EK certificate from TPM")
	result, err := tpm.SearchEKCertificate(tpm.TPMConfig{Logger: logger})
	if err != nil {
		return fmt.Errorf("failed to read EK certificate: %w", err)
	}
	logutil.LogDurationWithPadding(logger, startRead)

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
	logutil.LogWithPadding(logger, func() {
		logger.Info("download and verify integrity")
		logutil.LogDurationWithPadding(logger, startLoad)
	})

	logutil.LogWithPadding(logger, func() {
		metadata := trustedBundle.GetRootMetadata()
		logger.WithField("date", metadata.Date).
			WithField("commit", metadata.Commit).
			Debug("bundle's metadata")
		logger.Debugf("found %d vendors:", len(trustedBundle.GetVendors()))
		logutil.LogWithPadding(logger, func() {
			for _, v := range trustedBundle.GetVendors() {
				logger.WithField("id", v).
					Debug("vendor")
			}
		})
	})

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
	logutil.LogWithPadding(logger, func() {
		logger.WithField("id", result.Manufacturer.ASCII).Info("manufacturer supported")
	})

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
		EK:                  result.EK,
		SkipRevocationCheck: opts.skipRevocationCheck,
	}
	if err := checker.Check(checkCfg); err != nil {
		if errors.Is(err, validate.ErrUntrustedCertificate) {
			logutil.LogWithPadding(logger, func() {
				logger.Error("status: untrusted")
			})
			logger.Error("TPM is not genuine ✋")
			return internal.ErrSilence
		}
		return err
	}
	logutil.LogWithPadding(logger, func() {
		logger.Info("status: trusted")
		logutil.LogDuration(logger, startValidate)
	})
	logger.Info("TPM is genuine 🔒")
	return nil
}
