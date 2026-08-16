package runner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanSubmissionStageInstallationProducesExactSafeOrder(t *testing.T) {
	for _, completedProvider := range []bool{false, true} {
		stageID := "provider-prerequisites"
		if completedProvider {
			stageID = "cluster-lifecycle"
		}
		t.Run(stageID, func(t *testing.T) {
			fixture := submissionBundleFixture(t, completedProvider, "")
			packaged, err := BuildSubmissionStagePackage(submissionStagePackageConfig(t, fixture, stageID))
			if err != nil {
				t.Fatal(err)
			}
			plan, err := PlanSubmissionStageInstallation(packaged)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := packaged.Receipt()
			if err != nil {
				t.Fatal(err)
			}
			if plan.Format != SubmissionStageInstallationPlanFormat || plan.State != "VERIFIED" || plan.StageID != stageID || plan.PackageDigest != receipt.PackageDigest || plan.MutationAllowed {
				t.Fatalf("unexpected installation plan: %#v", plan)
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
				if create.Order != index+1 || create.Kind != wantKinds[index] || create.Namespace != submissionStageInputNamespace || create.PreflightMethod != "GET" || create.CreateMethod != "POST" || create.CollectionPath != wantCollections[index] || create.ObjectPath != create.CollectionPath+"/"+create.Name {
					t.Fatalf("unexpected create %d: %#v", index, create)
				}
				if !stageReceiptPrefixDigestPattern.MatchString(create.ObjectDigest) || strings.Contains(strings.ToLower(create.ObjectPath), "secret") {
					t.Fatalf("unsafe create identity: %#v", create)
				}
			}
			if plan.Creates[1].Name != plan.Creates[2].Name {
				t.Fatal("input or run identity differs across the installation plan")
			}
		})
	}
}

func TestPlanSubmissionStageInstallationRejectsChangedPackage(t *testing.T) {
	fixture := submissionBundleFixture(t, false, "")
	valid, err := BuildSubmissionStagePackage(submissionStagePackageConfig(t, fixture, "provider-prerequisites"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanSubmissionStageInstallation(VerifiedSubmissionStagePackage{}); err == nil {
		t.Fatal("unverified package was planned")
	}

	wrongInventory := valid
	wrongInventory.receipt.ObjectKinds = []string{"ConfigMap", "Job", "NetworkPolicy"}
	if _, err := PlanSubmissionStageInstallation(wrongInventory); err == nil {
		t.Fatal("changed object inventory was planned")
	}

	sharedCredential := valid
	sharedCredential.selectedCredential = sharedCredential.ledgerCredential
	if _, err := PlanSubmissionStageInstallation(sharedCredential); err == nil {
		t.Fatal("shared credential binding was planned")
	}

	foreignInstallationAuthority := valid
	foreignInstallationAuthority.installationAuthority = "ok-infra"
	foreignInstallationAuthority.ledgerAuthority = "ok-infra"
	if _, err := PlanSubmissionStageInstallation(foreignInstallationAuthority); err == nil {
		t.Fatal("foreign installation authority was planned")
	}

	changedRuntime := valid
	changedRuntime.raw = append([]byte(nil), valid.raw...)
	changedRuntime.raw = bytes.Replace(changedRuntime.raw, []byte("ok147-contract-executor-runtime"), []byte("ok147-foreign-runtime"), 1)
	changedRuntime.receipt.PackageDigest = digest.SHA256(changedRuntime.raw)
	if _, err := PlanSubmissionStageInstallation(changedRuntime); err == nil {
		t.Fatal("changed runtime identity was planned")
	}

	extraObject := valid
	extraObject.raw = append(append([]byte(nil), valid.raw...), []byte("\n---\napiVersion: v1\nkind: Secret\nmetadata: {name: forbidden}\n")...)
	extraObject.receipt.PackageDigest = digest.SHA256(extraObject.raw)
	if _, err := PlanSubmissionStageInstallation(extraObject); err == nil {
		t.Fatal("extra package object was planned")
	}
}
