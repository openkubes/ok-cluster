package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestRuntimeBindingMaterialCorrelatesPrivateRuntimeIdentity(t *testing.T) {
	config := runtimeBindingMaterialConfig(t)
	material, err := BuildRuntimeBindingMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := material.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := material.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != RuntimeBindingMaterialFormat || receipt.State != "VERIFIED" || receipt.StageID != "runtime-binding" || receipt.PersistentMutationAllowed || receipt.PrivateMaterialDigest != digest.SHA256(raw) || receipt.TargetClusterUIDDigest != digest.SHA256([]byte("cluster-runtime-uid-147")) {
		t.Fatalf("unexpected runtime binding receipt: %#v", receipt)
	}
	var private RuntimeBindingMaterial
	if err := json.Unmarshal(raw, &private); err != nil {
		t.Fatal(err)
	}
	if private.State != "CURRENT_RUNTIME_BOUND" || private.Target.CAPIClusterUID != "cluster-runtime-uid-147" || private.Target.WorkloadAPIEndpoint != "https://192.0.2.20:6443" || private.Target.WorkloadAPICAData == "" || private.Storage.Provisioner != "rancher.io/local-path" {
		t.Fatalf("private runtime identity differs: %#v", private)
	}
	public, _ := json.Marshal(receipt)
	for _, forbidden := range []string{"cluster-runtime-uid-147", "192.0.2.20", private.Target.WorkloadAPICAData, "kube-system-runtime-uid", "local-path-runtime-uid"} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("public receipt leaked private runtime value %q", forbidden)
		}
	}

	copyBytes, _ := material.Bytes()
	copyBytes[0] ^= 0xff
	again, _ := material.Bytes()
	if copyBytes[0] == again[0] {
		t.Fatal("runtime binding bytes are not defensive copies")
	}
	if _, err := (VerifiedRuntimeBindingMaterial{}).Receipt(); err == nil {
		t.Fatal("unverified runtime binding material exposed a receipt")
	}
}

func TestRuntimeBindingMaterialFailsClosed(t *testing.T) {
	valid := runtimeBindingMaterialConfig(t)
	for name, mutate := range map[string]func(*RuntimeBindingMaterialConfig){
		"wrong receipt prefix": func(config *RuntimeBindingMaterialConfig) { config.Bundle.Receipts = config.Bundle.Receipts[:4] },
		"replacement target": func(config *RuntimeBindingMaterialConfig) {
			binding, _ := loadWorkloadAuthorityBinding(config.WorkloadBindingPath, config.ExpectedWorkloadBindingDigest)
			binding.TargetClusterUID = "replacement-runtime-uid"
			writePlatformJSON(t, config.WorkloadBindingPath, binding)
			config.ExpectedWorkloadBindingDigest, _ = WorkloadAuthorityBindingDigest(binding)
		},
		"wrong CA": func(config *RuntimeBindingMaterialConfig) {
			os.WriteFile(config.WorkloadCAFile, []byte("foreign-ca"), 0o600)
		},
		"missing namespace": func(config *RuntimeBindingMaterialConfig) { config.Observation.KubeSystemUID = "" },
		"wrong provisioner": func(config *RuntimeBindingMaterialConfig) {
			config.Observation.LocalPathProvisioner = "foreign.example/storage"
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := cloneRuntimeBindingMaterialConfig(t, valid)
			mutate(&config)
			if _, err := BuildRuntimeBindingMaterial(config); err == nil {
				t.Fatal("unsafe runtime binding input was accepted")
			}
		})
	}
}

func runtimeBindingMaterialConfig(t *testing.T) RuntimeBindingMaterialConfig {
	t.Helper()
	bundle := runtimeBindingBundleConfig(t)
	plan, _, prefix, err := loadStageResumeWithPrefix(bundle)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	ca := testCA(t)
	caPath, bindingPath := filepath.Join(root, "workload-ca.crt"), filepath.Join(root, "workload-binding.json")
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	lifecycle, _ := prefix[1].Receipt()
	binding := WorkloadAuthorityBinding{
		Format: WorkloadAuthorityBindingFormat, IntentRevision: plan.IntentRevision,
		TargetClusterUID: "cluster-runtime-uid-147", TargetIdentityScheme: "capi-cluster-uid/v1",
		Endpoint: "https://192.0.2.20:6443", CABundleDigest: digest.SHA256(ca),
	}
	if digest.SHA256([]byte(binding.TargetClusterUID)) != lifecycle.TargetClusterUIDDigest {
		t.Fatal("test lifecycle target differs from workload binding")
	}
	writePlatformJSON(t, bindingPath, binding)
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeBindingMaterialConfig{
		Bundle: bundle, WorkloadBindingPath: bindingPath, ExpectedWorkloadBindingDigest: bindingDigest, WorkloadCAFile: caPath,
		Observation: RuntimeBindingObservation{KubeSystemUID: "kube-system-runtime-uid", LocalPathStorageClassUID: "local-path-runtime-uid", LocalPathProvisioner: "rancher.io/local-path"},
	}
}

func runtimeBindingBundleConfig(t *testing.T) StageResumeConfig {
	t.Helper()
	base := networkObservationBundleConfig(t, true)
	plan, _, prefix, err := loadStageResumeWithPrefix(base)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the lifecycle receipt's private target identity to match the
	// explicit runtime UID used by this materialization fixture.
	at := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	provider := prefix[0]
	lifecycle, err := stagereceipt.NewWithTargetClusterUIDDigest(plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, "SUCCEEDED", "ATTEMPTED", bundleSHA("3"), bundleSHA("4"), digest.SHA256([]byte("cluster-runtime-uid-147")), at.Add(-4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	lifecycleObservation, err := stagereceipt.New(plan, "lifecycle-observation", []stagereceipt.Verified{lifecycle}, "SUCCEEDED", "NOT_APPLICABLE", "", bundleSHA("5"), at.Add(-3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	enablement, err := stagereceipt.New(plan, "enablement", []stagereceipt.Verified{lifecycleObservation}, "SUCCEEDED", "ATTEMPTED", bundleSHA("6"), bundleSHA("7"), at.Add(-2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	network, err := stagereceipt.New(plan, "network-observation", []stagereceipt.Verified{enablement}, "SUCCEEDED", "NOT_APPLICABLE", "", bundleSHA("8"), at.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	base.Receipts = nil
	for index, item := range []stagereceipt.Verified{provider, lifecycle, lifecycleObservation, enablement, network} {
		raw, _ := item.Bytes()
		receiptDigest, _ := item.Digest()
		base.Receipts = append(base.Receipts, StageReceiptSource{Path: writeBundleFile(t, root, "receipt-"+string(rune('0'+index))+".json", raw), Digest: receiptDigest})
	}
	return base
}

func cloneRuntimeBindingMaterialConfig(t *testing.T, source RuntimeBindingMaterialConfig) RuntimeBindingMaterialConfig {
	t.Helper()
	root := t.TempDir()
	clone := source
	clone.Bundle.Receipts = append([]StageReceiptSource(nil), source.Bundle.Receipts...)
	for _, item := range []struct {
		source string
		target *string
	}{{source.WorkloadBindingPath, &clone.WorkloadBindingPath}, {source.WorkloadCAFile, &clone.WorkloadCAFile}} {
		raw, err := os.ReadFile(item.source)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, filepath.Base(item.source))
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		*item.target = path
	}
	return clone
}
