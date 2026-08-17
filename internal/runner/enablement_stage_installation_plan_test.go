package runner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanEnablementStageInstallationProducesExactSafeOrder(t *testing.T) {
	packaged, err := BuildEnablementStagePackage(enablementStagePackageConfig(t, enablementBundleFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanEnablementStageInstallation(packaged)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := packaged.Receipt()
	if plan.Format != EnablementStageInstallationPlanFormat || plan.State != "VERIFIED" || plan.StageID != "enablement" || plan.EnablementPackageDigest != receipt.PackageDigest || plan.Authority != "ok-mgmt" || plan.MutationAllowed {
		t.Fatalf("unexpected enablement installation plan: %#v", plan)
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
			t.Fatalf("unexpected enablement create %d: %#v", index, create)
		}
		if strings.Contains(strings.ToLower(create.ObjectPath), "secret") {
			t.Fatalf("installation plan unexpectedly contains credential path: %#v", create)
		}
	}
	if plan.Creates[1].Name != plan.Creates[2].Name {
		t.Fatal("enablement NetworkPolicy and Job run identities differ")
	}
}

func TestPlanEnablementStageInstallationFailsClosed(t *testing.T) {
	valid, err := BuildEnablementStagePackage(enablementStagePackageConfig(t, enablementBundleFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanEnablementStageInstallation(VerifiedEnablementStagePackage{}); err == nil {
		t.Fatal("unverified enablement package was planned")
	}
	tests := map[string]func(*VerifiedEnablementStagePackage){
		"wrong inventory": func(packaged *VerifiedEnablementStagePackage) {
			packaged.receipt.ObjectKinds = []string{"ConfigMap", "Job", "NetworkPolicy"}
		},
		"foreign authority": func(packaged *VerifiedEnablementStagePackage) { packaged.managementAuthority = "ok-infra" },
		"changed runtime": func(packaged *VerifiedEnablementStagePackage) {
			packaged.raw = bytes.Replace(packaged.raw, []byte("ok147-contract-executor-runtime"), []byte("ok147-foreign-runtime"), 1)
			packaged.receipt.PackageDigest = digest.SHA256(packaged.raw)
		},
		"changed credential": func(packaged *VerifiedEnablementStagePackage) {
			packaged.raw = bytes.Replace(packaged.raw, []byte(packaged.managementCredential), []byte("ok147-foreign-writer"), 1)
			packaged.receipt.PackageDigest = digest.SHA256(packaged.raw)
		},
		"extra object": func(packaged *VerifiedEnablementStagePackage) {
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
			if _, err := PlanEnablementStageInstallation(packaged); err == nil {
				t.Fatal("changed enablement package was planned")
			}
		})
	}
}
