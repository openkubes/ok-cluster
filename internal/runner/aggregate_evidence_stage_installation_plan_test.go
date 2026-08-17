package runner

import (
	"bytes"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanAggregateEvidenceStageInstallationBindsThreePublicObjects(t *testing.T) {
	packaged, err := BuildAggregateEvidenceStagePackage(aggregateEvidenceStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanAggregateEvidenceStageInstallation(packaged)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := packaged.Receipt()
	if plan.Format != AggregateEvidenceStageInstallationPlanFormat || plan.State != "VERIFIED" || plan.StageID != "aggregate-evidence" || plan.EvidencePackageDigest != receipt.PackageDigest || plan.Authority != "ok-mgmt" || plan.MutationAllowed || len(plan.Creates) != 3 {
		t.Fatalf("unexpected aggregate evidence installation plan: %#v", plan)
	}
	wantKinds := []string{"ConfigMap", "NetworkPolicy", "Job"}
	for index, create := range plan.Creates {
		if create.Order != index+1 || create.Kind != wantKinds[index] || create.Namespace != submissionStageInputNamespace || create.PreflightMethod != "GET" || create.CreateMethod != "POST" || !stageReceiptPrefixDigestPattern.MatchString(create.ObjectDigest) {
			t.Fatalf("unexpected aggregate evidence create %d: %#v", index, create)
		}
	}
	plan.Creates[0].Name = "changed"
	again, err := PlanAggregateEvidenceStageInstallation(packaged)
	if err != nil || again.Creates[0].Name == "changed" {
		t.Fatal("caller mutated retained aggregate evidence installation plan")
	}
}

func TestPlanAggregateEvidenceStageInstallationFailsClosed(t *testing.T) {
	packaged, err := BuildAggregateEvidenceStagePackage(aggregateEvidenceStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	oldName := []byte(packaged.runtimeSecret)
	newName := []byte("ok147-runtime-binding-run-02")
	if len(oldName) != len(newName) || !bytes.Contains(packaged.raw, oldName) {
		t.Fatal("aggregate runtime Secret fixture is unavailable")
	}
	packaged.raw = bytes.Replace(packaged.raw, oldName, newName, 1)
	parts := bytes.SplitN(packaged.raw, []byte("\n---\n"), 2)
	packaged.receipt.PackageDigest = digest.SHA256(packaged.raw)
	packaged.receipt.JobEnvelopeDigest = digest.SHA256(parts[1])
	if _, err := PlanAggregateEvidenceStageInstallation(packaged); err == nil {
		t.Fatal("aggregate evidence Job with foreign private input was accepted")
	}

	packaged, err = BuildAggregateEvidenceStagePackage(aggregateEvidenceStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	packaged.receipt.ObjectKinds = []string{"ConfigMap", "Job", "NetworkPolicy"}
	if _, err := PlanAggregateEvidenceStageInstallation(packaged); err == nil {
		t.Fatal("aggregate evidence object reordering was accepted")
	}
	if _, err := PlanAggregateEvidenceStageInstallation(VerifiedAggregateEvidenceStagePackage{}); err == nil {
		t.Fatal("unverified aggregate evidence package was accepted")
	}
}
