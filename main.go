package main

import (
	"errors"
	"os"

	goversion "github.com/caarlos0/go-version"
	"github.com/caarlos0/log"
	"github.com/loicsikidi/tpm-trust/cmd/audit"
	versionCmd "github.com/loicsikidi/tpm-trust/cmd/version"
	"github.com/loicsikidi/tpm-trust/internal"
	"github.com/spf13/cobra"
)

const website = "https://github.com/loicsikidi/tpm-trust"

var (
	version = ""
	builtBy = ""
)

func main() {
	rootCmd := &cobra.Command{
		Use:           "tpm-trust",
		Short:         "",
		Long:          ``,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(audit.NewCommand())
	rootCmd.AddCommand(versionCmd.NewCommand(buildVersion(version, builtBy)))

	if err := rootCmd.Execute(); err != nil {
		if !errors.Is(err, internal.ErrSilence) {
			log.WithError(err).Error("command failed")
		}
		os.Exit(1)
	}
}

func buildVersion(version, builtBy string) goversion.Info {
	return goversion.GetVersionInfo(
		goversion.WithAppDetails("tpmtb", "TPM root of trust, simplified.", website),
		func(i *goversion.Info) {
			if version != "" {
				i.GitVersion = version
			}
			if builtBy != "" {
				i.BuiltBy = builtBy
			}
		},
	)
}
