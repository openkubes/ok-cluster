package runner

import "errors"

// validateTokenOnlyAuthority is an I/O-free execution-adapter guard. A set
// KubeconfigFile is always unsupported, including when TokenFile is also set.
// Never silently select one credential or inspect the unsupported file. Passing
// this check is not approval of a token, authority, stage, or bootstrap profile.
func validateTokenOnlyAuthority(config KubernetesAuthorityConfig) error {
	if config.KubeconfigFile != "" {
		return ErrClientCertificateDisabled
	}
	if config.TokenFile == "" {
		return errors.New("Kubernetes authority requires exactly one transport credential")
	}
	return nil
}
