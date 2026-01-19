package tpm

import (
	"fmt"

	"github.com/loicsikidi/attest"
	"github.com/loicsikidi/attest/info"
)

// Info retrieves static information about the TPM.
// It opens the TPM device, retrieves information, and returns it as [info.TPMInfo].
func Info(cfg TPMConfig) (*info.TPMInfo, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	logger := cfg.Logger
	logger.IncreasePadding()
	defer logger.ResetPadding()

	logger.Debug("open connection to TPM")
	tpm, err := attest.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer func() {
		logger.Debug("closing connection to TPM")
		if closeErr := tpm.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close TPM: %w (original error: %v)", closeErr, err)
		}
	}()

	logger.Debug("getting TPM info")
	tpmInfo, err := tpm.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM info: %w", err)
	}

	return tpmInfo, nil
}
