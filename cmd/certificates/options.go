package certificates

import "github.com/google/go-tpm/tpm2/transport"

type tpmsimulator transport.TPMCloser

type options interface {
	getSimulator() tpmsimulator
}

// needsPrivileges checks if the current operation requires elevated privileges.
func needsPrivileges(opts options) bool {
	return opts.getSimulator() == nil
}
