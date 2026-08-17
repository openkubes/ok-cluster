package runner

import (
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildRuntimeBindingStageRuntimePrerequisiteBindsExactPackage(t *testing.T) {
	packaged, err := BuildRuntimeBindingStagePackage(runtimeBindingStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	runtime, err := BuildRuntimeBindingStageRuntimePrerequisite(packaged, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := runtime.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	packageReceipt, _ := packaged.Receipt()
	if receipt.Format != RuntimeBindingStageRuntimePrerequisiteFormat || receipt.State != "VERIFIED" || receipt.BindingPackageDigest != packageReceipt.PackageDigest || receipt.Authority != "ok-mgmt" || receipt.Namespace != submissionStageInputNamespace || receipt.Name != "ok147-contract-executor-runtime" || receipt.ManifestDigest != digest.SHA256(manifest) || receipt.ObjectDigest != digest.SHA256(runtime.raw) || receipt.MutationAllowed {
		t.Fatalf("unexpected runtime binding runtime receipt: %#v", receipt)
	}
}

func TestBuildRuntimeBindingStageRuntimePrerequisiteFailsClosed(t *testing.T) {
	packaged, err := BuildRuntimeBindingStagePackage(runtimeBindingStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	manifest := submissionStageRuntimeManifest(t)
	if _, err := BuildRuntimeBindingStageRuntimePrerequisite(VerifiedRuntimeBindingStagePackage{}, manifest, digest.SHA256(manifest)); err == nil {
		t.Fatal("unverified runtime binding package accepted")
	}
	if _, err := BuildRuntimeBindingStageRuntimePrerequisite(packaged, append(manifest, '\n'), digest.SHA256(manifest)); err == nil {
		t.Fatal("changed runtime binding runtime manifest accepted")
	}
	runtime, err := BuildRuntimeBindingStageRuntimePrerequisite(packaged, manifest, digest.SHA256(manifest))
	if err != nil {
		t.Fatal(err)
	}
	runtime.raw[0] = 'x'
	if _, err := runtime.Receipt(); err == nil {
		t.Fatal("changed runtime binding runtime object accepted")
	}
}
