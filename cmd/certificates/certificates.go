package certificates

import (
	"github.com/spf13/cobra"
)

// NewCommand creates the certificates parent command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificates",
		Short: "manage TPM EK certificates",
		Long:  `Commands to list and inspect Endorsement Key (EK) certificates from the TPM.`,
	}

	cmd.AddCommand(newListCommand())
	cmd.AddCommand(newGetCommand())

	return cmd
}
