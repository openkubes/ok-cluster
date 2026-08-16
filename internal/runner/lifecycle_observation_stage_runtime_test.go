package runner

import (
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildLifecycleObservationStageRuntimePrerequisiteBindsExactPackage(t *testing.T) {
	packaged, err := BuildLifecycleObservationStagePackage(lifecycleObservationStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	runtime, err := BuildLifecycleObservationStageRuntimePrerequisite(packaged, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := runtime.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	packageReceipt, _ := packaged.Receipt()
	if receipt.Format != LifecycleObservationStageRuntimePrerequisiteFormat || receipt.State != "VERIFIED" || receipt.ObservationPackageDigest != packageReceipt.PackageDigest || receipt.Authority != "ok-mgmt" || receipt.Namespace != submissionStageInputNamespace || receipt.Name != "ok147-contract-executor-runtime" || receipt.ManifestDigest != digest.SHA256(manifest) || receipt.ObjectDigest != digest.SHA256(runtime.raw) || receipt.MutationAllowed {
		t.Fatalf("unexpected lifecycle observation runtime receipt: %#v", receipt)
	}
}

func TestBuildLifecycleObservationStageRuntimePrerequisiteFailsClosed(t *testing.T) {
	packaged, err := BuildLifecycleObservationStagePackage(lifecycleObservationStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	if _, err := BuildLifecycleObservationStageRuntimePrerequisite(VerifiedLifecycleObservationStagePackage{}, manifest, digest.SHA256(manifest)); err == nil {
		t.Fatal("unverified observation package accepted")
	}
	if _, err := BuildLifecycleObservationStageRuntimePrerequisite(packaged, append(manifest, '\n'), digest.SHA256(manifest)); err == nil {
		t.Fatal("changed runtime manifest accepted")
	}
	runtime, err := BuildLifecycleObservationStageRuntimePrerequisite(packaged, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	runtime.raw[0] = 'x'
	if _, err := runtime.Receipt(); err == nil {
		t.Fatal("changed runtime object accepted")
	}
}
