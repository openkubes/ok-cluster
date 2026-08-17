package runner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanRuntimeBindingStageInstallationProducesExactSafeOrder(t *testing.T) {
	packaged, err := BuildRuntimeBindingStagePackage(runtimeBindingStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanRuntimeBindingStageInstallation(packaged)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := packaged.Receipt()
	if plan.Format != RuntimeBindingStageInstallationPlanFormat || plan.State != "VERIFIED" || plan.StageID != "runtime-binding" || plan.StagePackageDigest != receipt.PackageDigest || plan.Authority != "ok-mgmt" || plan.MutationAllowed {
		t.Fatalf("unexpected runtime binding installation plan: %#v", plan)
	}
	wantKinds := []string{"ConfigMap", "NetworkPolicy", "Job"}
	wantCollections := []string{
		"/api/v1/namespaces/openkubes-execution-system/configmaps",
		"/apis/networking.k8s.io/v1/namespaces/openkubes-execution-system/networkpolicies",
		"/apis/batch/v1/namespaces/openkubes-execution-system/jobs",
	}
	if len(plan.Creates) != len(wantKinds) {
		t.Fatalf("creates=%d, want 3", len(plan.Creates))
	}
	for index, create := range plan.Creates {
		if create.Order != index+1 || create.Kind != wantKinds[index] || create.Namespace != submissionStageInputNamespace || create.PreflightMethod != "GET" || create.CreateMethod != "POST" || create.CollectionPath != wantCollections[index] || create.ObjectPath != create.CollectionPath+"/"+create.Name || !stageReceiptPrefixDigestPattern.MatchString(create.ObjectDigest) {
			t.Fatalf("unexpected runtime binding create %d: %#v", index, create)
		}
		if strings.Contains(strings.ToLower(create.ObjectPath), "secret") {
			t.Fatalf("installation plan unexpectedly contains credential path: %#v", create)
		}
	}
	if plan.Creates[1].Name != plan.Creates[2].Name {
		t.Fatal("NetworkPolicy and Job run identities differ")
	}
}

func TestPlanRuntimeBindingStageInstallationFailsClosed(t *testing.T) {
	valid, err := BuildRuntimeBindingStagePackage(runtimeBindingStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanRuntimeBindingStageInstallation(VerifiedRuntimeBindingStagePackage{}); err == nil {
		t.Fatal("unverified runtime binding package was planned")
	}
	tests := map[string]func(*VerifiedRuntimeBindingStagePackage){
		"wrong inventory": func(packaged *VerifiedRuntimeBindingStagePackage) {
			packaged.receipt.ObjectKinds = []string{"ConfigMap", "Job", "NetworkPolicy"}
		},
		"foreign authority": func(packaged *VerifiedRuntimeBindingStagePackage) {
			packaged.managementAuthority = "ok-infra"
		},
		"changed runtime": func(packaged *VerifiedRuntimeBindingStagePackage) {
			packaged.raw = bytes.Replace(packaged.raw, []byte("ok147-contract-executor-runtime"), []byte("ok147-foreign-runtime"), 1)
			packaged.receipt.PackageDigest = digest.SHA256(packaged.raw)
		},
		"changed persistence credential": func(packaged *VerifiedRuntimeBindingStagePackage) {
			packaged.raw = bytes.Replace(packaged.raw, []byte(packaged.persistenceCredential), []byte("ok147-foreign-persistence"), 1)
			packaged.receipt.PackageDigest = digest.SHA256(packaged.raw)
		},
		"changed workload credential": func(packaged *VerifiedRuntimeBindingStagePackage) {
			packaged.raw = bytes.Replace(packaged.raw, []byte(packaged.workloadCredential), []byte("ok147-foreign-workload"), 1)
			packaged.receipt.PackageDigest = digest.SHA256(packaged.raw)
		},
		"extra object": func(packaged *VerifiedRuntimeBindingStagePackage) {
			packaged.raw = append(packaged.raw, []byte("\n---\napiVersion: v1\nkind: Secret\nmetadata: {name: forbidden}\n")...)
			packaged.receipt.PackageDigest = digest.SHA256(packaged.raw)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			packaged := valid
			packaged.raw = append([]byte(nil), valid.raw...)
			packaged.receipt.ObjectKinds = append([]string(nil), valid.receipt.ObjectKinds...)
			mutate(&packaged)
			if _, err := PlanRuntimeBindingStageInstallation(packaged); err == nil {
				t.Fatal("changed runtime binding package was planned")
			}
		})
	}
}
