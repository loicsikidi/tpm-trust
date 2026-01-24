package info

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/loicsikidi/attest/info"
	"github.com/loicsikidi/tpm-trust/internal/log"
	"github.com/loicsikidi/tpm-trust/internal/logutil"
	"github.com/loicsikidi/tpm-trust/internal/privilege"
	"github.com/loicsikidi/tpm-trust/internal/tpm"
	"github.com/spf13/cobra"
)

type options struct {
	format  string
	verbose bool
}

// Check validates the options.
func (o *options) Check() error {
	switch o.format {
	case "text", "json":
		return nil
	default:
		return fmt.Errorf("unsupported format %q (supported: text, json)", o.format)
	}
}

func NewCommand() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "info",
		Short: "display TPM information",
		Long: `Display static information about the TPM including vendor, manufacturer,
firmware version, supported algorithms, and more.`,
		Example: `  # Display TPM info in text format
  tpm-trust beta info

  # Display TPM info in JSON format
  tpm-trust beta info --format json

  # Display TPM info with verbose logging
  tpm-trust beta info --verbose`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), opts)
		},
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&opts.format, "format", "f", "text", "Output format (text or json)")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "Enable verbose logging")

	return cmd
}

func run(_ context.Context, opts *options) error {
	if err := opts.Check(); err != nil {
		return err
	}

	// In JSON mode, we want to suppress logs to keep output clean
	var logger log.Logger
	if opts.format == "json" {
		logger = log.New(log.WithNoop())
	} else {
		logger = log.New(log.WithVerbose(opts.verbose))
	}

	if err := privilege.Elevate(); err != nil {
		return fmt.Errorf("failed to elevate privileges: %w", err)
	}

	startRead := time.Now()
	logger.Info("Reading TPM information")

	tpmInfo, err := tpm.Info(tpm.TPMConfig{Logger: logger})
	if err != nil {
		return fmt.Errorf("failed to read TPM info: %w", err)
	}

	logutil.LogDurationWithPadding(logger, startRead)

	switch opts.format {
	case "json":
		return outputJSON(tpmInfo)
	default: // text
		return outputText(logger, tpmInfo)
	}
}

func outputJSON(tpmInfo *info.TPMInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(tpmInfo); err != nil {
		return fmt.Errorf("failed to encode TPM info as JSON: %w", err)
	}
	return nil
}

func outputText(logger log.Logger, tpmInfo *info.TPMInfo) error {
	logger.Info("TPM Information")
	logutil.LogWithPadding(logger, func() {
		logger.WithField("vendor", tpmInfo.Vendor).Info("Vendor")
		logger.WithField("id", tpmInfo.Manufacturer.ASCII).
			WithField("name", tpmInfo.Manufacturer.Name).
			Info("Manufacturer")
		logger.WithField("revision", tpmInfo.Revision).Info("Revision")
		logger.WithField("major", tpmInfo.FirmwareVersion.Major).
			WithField("minor", tpmInfo.FirmwareVersion.Minor).
			Info("Firmware Version")

		if len(tpmInfo.Algorithms) > 0 {
			logger.Infof("Supported Algorithms (%d):", len(tpmInfo.Algorithms))
			logutil.LogWithPadding(logger, func() {
				for _, alg := range tpmInfo.Algorithms {
					logger.Info(alg.String())
				}
			})
		}

		if len(tpmInfo.KeyTypes) > 0 {
			logger.Infof("Supported Key Types (%d):", len(tpmInfo.KeyTypes))
			logutil.LogWithPadding(logger, func() {
				for _, kty := range tpmInfo.KeyTypes {
					logger.Info(kty.String())
				}
			})
		}

		if tpmInfo.NVMaxBufferSize > 0 {
			logger.WithField("bytes", tpmInfo.NVMaxBufferSize).Info("NV Max Buffer Size")
		}

		if tpmInfo.NVIndexMaxSize > 0 {
			logger.WithField("bytes", tpmInfo.NVIndexMaxSize).Info("NV Index Max Size")
		}

		if len(tpmInfo.PcrBanks) > 0 {
			logger.Infof("PCR Banks (%d):", len(tpmInfo.PcrBanks))
			logutil.LogWithPadding(logger, func() {
				for _, bank := range tpmInfo.PcrBanks {
					logger.WithField("pcrs", len(bank.PCRs)).
						Info(bank.Alg.String())
				}
			})
		}

		logger.WithField("present", tpmInfo.HasEKCertChains()).Info("EK Certificate Chains")

		if tpmInfo.HasEKCertChains() {
			logger.Infof("EK Certificate Chains (%d certificates)", len(tpmInfo.EKCertChains))
			logutil.LogWithPadding(logger, func() {
				for i, cert := range tpmInfo.EKCertChains {
					logger.
						WithField("subject", cert.Subject).
						WithField("issuer", cert.Issuer).
						Infof("index %d", i)
				}
			})
		}
	})

	return nil
}
