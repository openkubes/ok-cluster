package runner

import (
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildEnablementStageRuntimePrerequisiteBindsExactPackage(t *testing.T) {
	packaged, err := BuildEnablementStagePackage(enablementStagePackageConfig(t, enablementBundleFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	runtime, err := BuildEnablementStageRuntimePrerequisite(packaged, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := runtime.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	packageReceipt, _ := packaged.Receipt()
	if receipt.Format != EnablementStageRuntimePrerequisiteFormat || receipt.State != "VERIFIED" || receipt.EnablementPackageDigest != packageReceipt.PackageDigest || receipt.Authority != "ok-mgmt" || receipt.Namespace != submissionStageInputNamespace || receipt.Name != "ok147-contract-executor-runtime" || receipt.ManifestDigest != digest.SHA256(manifest) || receipt.ObjectDigest != digest.SHA256(runtime.raw) || receipt.MutationAllowed {
		t.Fatalf("unexpected enablement runtime receipt: %#v", receipt)
	}
}

func TestBuildEnablementStageRuntimePrerequisiteFailsClosed(t *testing.T) {
	packaged, err := BuildEnablementStagePackage(enablementStagePackageConfig(t, enablementBundleFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	if _, err := BuildEnablementStageRuntimePrerequisite(VerifiedEnablementStagePackage{}, manifest, digest.SHA256(manifest)); err == nil {
		t.Fatal("unverified enablement package accepted")
	}
	if _, err := BuildEnablementStageRuntimePrerequisite(packaged, append(manifest, '\n'), digest.SHA256(manifest)); err == nil {
		t.Fatal("changed enablement runtime manifest accepted")
	}
	runtime, err := BuildEnablementStageRuntimePrerequisite(packaged, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	runtime.raw[0] = 'x'
	if _, err := runtime.Receipt(); err == nil {
		t.Fatal("changed enablement runtime object accepted")
	}
}
