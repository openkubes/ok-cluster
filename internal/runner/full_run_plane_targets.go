package runner

import (
	"errors"
	"fmt"

	"github.com/openkubes/ok-cluster/internal/kubeconfigtarget"
)

// VerifyFullRunManifestPlaneTargets adds an offline target/trust check for an
// explicitly selected friendly-YAML reference. The existing manifest retains
// all credential/authority semantics; no client or executor is opened here.
func VerifyFullRunManifestPlaneTargets(path, expectedDigest string, management, infrastructure kubeconfigtarget.Target) error {
	manifest, _, err := LoadFullRunExecutionManifest(path)
	if err != nil {
		return fmt.Errorf("target comparison requires a verified full-run manifest: %w", err)
	}
	return verifyFullRunManifestPlaneTargets(manifest, expectedDigest, management, infrastructure)
}

// Structural comparison only. Callers cannot promote this into execution:
// the public entry point above must pass the credential-policy loader first.
func verifyFullRunManifestPlaneTargets(manifest VerifiedFullRunExecutionManifest, expectedDigest string, management, infrastructure kubeconfigtarget.Target) error {
	if !manifest.verified || manifest.receipt.State != "VERIFIED" || manifest.receipt.ManifestDigest != expectedDigest {
		return errors.New("target comparison requires the same verified full-run manifest")
	}
	for _, ref := range []struct {
		target    kubeconfigtarget.Target
		authority postRuntimeAuthorityDocument
	}{
		{management, manifest.document.ClusterLifecycle.Authority},
		{management, manifest.document.LifecycleObservation.Management},
		{management, manifest.document.Enablement.Runtime.Authority},
		{management, manifest.document.NetworkObservation.Management},
		{infrastructure, manifest.document.ProviderPrerequisites.Authority},
	} {
		ca, err := readBoundedRegular(ref.authority.CAFile, maximumCABytes)
		if err != nil || ref.target.MatchTransport(ref.authority.Endpoint, ca) != nil {
			return errors.New("selected management/infrastructure kubeconfig target differs from bound runner authority")
		}
	}
	provider, err := kubeconfigtarget.ReadCurrent(manifest.document.ProviderAccess.KubeconfigFile)
	if err != nil || provider.Endpoint != infrastructure.Endpoint || provider.CATrustDigest != infrastructure.CATrustDigest {
		return errors.New("provider-access credential targets a different infrastructure cluster or CA")
	}
	return nil
}
