package beta

import (
	"github.com/loicsikidi/tpm-trust/cmd/beta/info"
	"github.com/spf13/cobra"
)

// NewCommand creates the beta command with its subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "beta",
		Short: "beta commands (experimental features)",
		Long:  `Beta commands provide access to experimental features that may change in future releases.`,
	}

	cmd.AddCommand(info.NewCommand())

	return cmd
}
