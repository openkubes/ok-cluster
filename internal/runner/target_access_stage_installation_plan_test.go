package runner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanTargetAccessStageInstallationProducesExactSafeOrder(t *testing.T) {
	packaged, err := BuildTargetAccessStagePackage(targetAccessStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanTargetAccessStageInstallation(packaged)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := packaged.Receipt()
	if plan.Format != TargetAccessStageInstallationPlanFormat || plan.State != "VERIFIED" || plan.StageID != "target-access" || plan.StagePackageDigest != receipt.PackageDigest || plan.Authority != receipt.TargetIdentityDigest || plan.MutationAllowed {
		t.Fatalf("unexpected target-access installation plan: %#v", plan)
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
			t.Fatalf("unexpected target-access create %d: %#v", index, create)
		}
		if strings.Contains(strings.ToLower(create.ObjectPath), "secret") {
			t.Fatalf("installation plan unexpectedly contains credential path: %#v", create)
		}
	}
	if plan.Creates[1].Name != plan.Creates[2].Name {
		t.Fatal("target-access NetworkPolicy and Job run identities differ")
	}
}

func TestPlanTargetAccessStageInstallationFailsClosed(t *testing.T) {
	valid, err := BuildTargetAccessStagePackage(targetAccessStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanTargetAccessStageInstallation(VerifiedTargetAccessStagePackage{}); err == nil {
		t.Fatal("unverified target-access package was planned")
	}
	tests := map[string]func(*VerifiedTargetAccessStagePackage){
		"wrong inventory": func(packaged *VerifiedTargetAccessStagePackage) {
			packaged.receipt.ObjectKinds = []string{"ConfigMap", "Job", "NetworkPolicy"}
		},
		"foreign authority": func(packaged *VerifiedTargetAccessStagePackage) {
			packaged.workloadAuthority = bundleSHA("1")
		},
		"changed runtime": func(packaged *VerifiedTargetAccessStagePackage) {
			packaged.raw = bytes.Replace(packaged.raw, []byte("ok147-contract-executor-runtime"), []byte("ok147-foreign-runtime"), 1)
			updateTargetAccessPackageDigests(packaged)
		},
		"changed workload credential": func(packaged *VerifiedTargetAccessStagePackage) {
			packaged.raw = bytes.Replace(packaged.raw, []byte(packaged.workloadCredential), []byte("ok147-foreign-workload"), 1)
			updateTargetAccessPackageDigests(packaged)
		},
		"broadened egress": func(packaged *VerifiedTargetAccessStagePackage) {
			packaged.raw = bytes.Replace(packaged.raw, []byte("  egress:\n"), []byte("  egress:\n    - {}\n"), 1)
			updateTargetAccessPackageDigests(packaged)
		},
		"extra object": func(packaged *VerifiedTargetAccessStagePackage) {
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
			if _, err := PlanTargetAccessStageInstallation(packaged); err == nil {
				t.Fatal("changed target-access package was planned")
			}
		})
	}
}

func updateTargetAccessPackageDigests(packaged *VerifiedTargetAccessStagePackage) {
	packaged.receipt.PackageDigest = digest.SHA256(packaged.raw)
	documents := bytes.SplitN(packaged.raw, []byte("\n---\n"), 2)
	if len(documents) == 2 {
		packaged.receipt.JobEnvelopeDigest = digest.SHA256(documents[1])
	}
}
