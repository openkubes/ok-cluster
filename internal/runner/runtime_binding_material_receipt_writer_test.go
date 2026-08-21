package runner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

func TestPersistRuntimeBindingMaterialReceiptWritesVerifiedPrivateHandoff(t *testing.T) {
	materialPath, receiptPath, receipt := runtimeBindingMaterialReceiptWriterFixture(t)
	if err := persistRuntimeBindingMaterialReceipt(receipt, materialPath, receiptPath, receipt.PlanDigest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(receiptPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("private material receipt metadata differs: %#v %v", info, err)
	}
	raw, err := readBoundedRegular(receiptPath, maximumRuntimeBindingMaterialFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	var stored RuntimeBindingMaterialReceipt
	if err := jsonstrict.Decode(raw, &stored); err != nil || stored != receipt {
		t.Fatalf("stored material receipt differs: %#v %v", stored, err)
	}
	if err := persistRuntimeBindingMaterialReceipt(receipt, materialPath, receiptPath, receipt.PlanDigest); err == nil {
		t.Fatal("existing material receipt was overwritten")
	}
}

func TestPersistRuntimeBindingMaterialReceiptRejectsUnsafeOrDifferentInputs(t *testing.T) {
	for name, mutate := range map[string]func(string, string, *RuntimeBindingMaterialReceipt){
		"different material digest": func(_, _ string, receipt *RuntimeBindingMaterialReceipt) {
			receipt.PrivateMaterialDigest = runnerStageSHA("f")
		},
		"different plan": func(_, _ string, receipt *RuntimeBindingMaterialReceipt) {
			receipt.PlanDigest = runnerStageSHA("e")
		},
		"existing destination": func(_, receiptPath string, _ *RuntimeBindingMaterialReceipt) {
			if err := os.WriteFile(receiptPath, []byte("existing"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink destination": func(_, receiptPath string, _ *RuntimeBindingMaterialReceipt) {
			target := filepath.Join(filepath.Dir(receiptPath), "target")
			if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, receiptPath); err != nil {
				t.Fatal(err)
			}
		},
		"noncanonical material": func(materialPath, _ string, _ *RuntimeBindingMaterialReceipt) {
			raw, err := os.ReadFile(materialPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(materialPath, append(raw, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			materialPath, receiptPath, receipt := runtimeBindingMaterialReceiptWriterFixture(t)
			planDigest := receipt.PlanDigest
			mutate(materialPath, receiptPath, &receipt)
			if err := persistRuntimeBindingMaterialReceipt(receipt, materialPath, receiptPath, planDigest); err == nil {
				t.Fatal("unsafe or different runtime binding receipt input was accepted")
			}
		})
	}
}

func runtimeBindingMaterialReceiptWriterFixture(t *testing.T) (string, string, RuntimeBindingMaterialReceipt) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	materialPath := filepath.Join(directory, "runtime-binding.json")
	receiptPath := filepath.Join(directory, "runtime-binding-receipt.json")
	material := RuntimeBindingMaterial{
		Format: RuntimeBindingMaterialFormat, State: "CURRENT_RUNTIME_BOUND", PlanDigest: runnerStageSHA("1"),
		IntentRevision: runnerStageSHA("2"), EnablementRevision: runnerStageSHA("3"),
		PlatformRevision: runnerStageSHA("4"), ExecutionFixture: runnerStageSHA("5"),
		Target: RuntimeBindingTarget{
			Name: "disposable-ok147", CAPIClusterUID: "11111111-1111-4111-8111-111111111111",
			TargetIdentityScheme: "capi-cluster-uid", WorkloadAPIEndpoint: "https://runtime.invalid:6443",
			WorkloadAPICAData: "Y2E=", WorkloadAPICADigest: runnerStageSHA("6"),
			KubeSystemUID: "22222222-2222-4222-8222-222222222222",
		},
		Storage:  RuntimeBindingStorage{Name: "local-path", UID: "33333333-3333-4333-8333-333333333333", Provisioner: "rancher.io/local-path"},
		Evidence: RuntimeBindingEvidence{LifecycleEvidenceDigest: runnerStageSHA("7"), NetworkEvidenceDigest: runnerStageSHA("8")},
	}
	raw, err := canonicalRuntimeBinding(material)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(materialPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	receipt := RuntimeBindingMaterialReceipt{
		Format: RuntimeBindingMaterialFormat, State: "VERIFIED", StageID: "runtime-binding",
		PlanDigest: material.PlanDigest, IntentRevision: material.IntentRevision,
		TargetClusterUIDDigest: digest.SHA256([]byte(material.Target.CAPIClusterUID)), WorkloadAPICADigest: material.Target.WorkloadAPICADigest,
		KubeSystemUIDDigest: digest.SHA256([]byte(material.Target.KubeSystemUID)), LocalPathStorageUIDDigest: digest.SHA256([]byte(material.Storage.UID)),
		LifecycleEvidenceDigest: material.Evidence.LifecycleEvidenceDigest, NetworkEvidenceDigest: material.Evidence.NetworkEvidenceDigest,
		PrivateMaterialDigest: digest.SHA256(raw), PersistentMutationAllowed: false,
	}
	return materialPath, receiptPath, receipt
}

func TestPersistRuntimeBindingMaterialReceiptLeavesAbsentDestinationOnVerificationFailure(t *testing.T) {
	materialPath, receiptPath, receipt := runtimeBindingMaterialReceiptWriterFixture(t)
	receipt.KubeSystemUIDDigest = runnerStageSHA("f")
	if err := persistRuntimeBindingMaterialReceipt(receipt, materialPath, receiptPath, receipt.PlanDigest); err == nil {
		t.Fatal("different runtime identity was accepted")
	}
	if _, err := os.Lstat(receiptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verification failure wrote a receipt: %v", err)
	}
}
