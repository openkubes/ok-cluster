package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestOpenKubernetesEnablementStageOperationBindsManagement(t *testing.T) {
	plan := runnerStagedPlan(t)
	config := runnerEnablementOperationConfig(t, plan)
	operation, err := OpenKubernetesEnablementStageOperation(config)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Ledger == nil || operation.Mutator == nil || operation.Clock == nil {
		t.Fatalf("incomplete enablement operation: %#v", operation)
	}
	binding := operation.Mutator.Binding()
	if binding.StageID != "enablement" || binding.Operation != "CreateEnablement" || binding.PlanDigest != plan.PlanDigest {
		t.Fatalf("operation bound a different stage: %#v", binding)
	}
}

func TestOpenKubernetesEnablementStageOperationRejectsForeignInputs(t *testing.T) {
	plan := runnerStagedPlan(t)
	config := runnerEnablementOperationConfig(t, plan)
	config.Authority.AuthorityIdentity = plan.Authorities.Infrastructure
	if _, err := OpenKubernetesEnablementStageOperation(config); err == nil {
		t.Fatal("foreign enablement authority was accepted")
	}

	config = runnerEnablementOperationConfig(t, plan)
	ledgerToken, err := os.ReadFile(config.Ledger.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.Authority.TokenFile, ledgerToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKubernetesEnablementStageOperation(config); err == nil {
		t.Fatal("shared ledger and enablement credential was accepted")
	}

	config = runnerEnablementOperationConfig(t, plan)
	config.Projection.EnablementRevision = runnerStageSHA("0")
	if _, err := OpenKubernetesEnablementStageOperation(config); err == nil {
		t.Fatal("foreign enablement projection was accepted")
	}

	config = runnerEnablementOperationConfig(t, plan)
	config.Clock = nil
	if _, err := OpenKubernetesEnablementStageOperation(config); err == nil {
		t.Fatal("missing enablement clock was accepted")
	}
}

func runnerEnablementOperationConfig(t *testing.T, plan stageplan.Binding) KubernetesEnablementStageOperationConfig {
	t.Helper()
	root := t.TempDir()
	caPath := filepath.Join(root, "ca.crt")
	ledgerToken := filepath.Join(root, "ledger-token")
	authorityToken := filepath.Join(root, "authority-token")
	for path, value := range map[string][]byte{
		caPath: testCA(t), ledgerToken: []byte("short-lived-ledger-token"), authorityToken: []byte("short-lived-enablement-token"),
	} {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return KubernetesEnablementStageOperationConfig{
		Ledger:    KubernetesLedgerConfig{Endpoint: "https://192.0.2.12:6443", Namespace: "openkubes-execution-system", TokenFile: ledgerToken, CAFile: caPath},
		Authority: KubernetesAuthorityConfig{Endpoint: "https://192.0.2.12:6443", AuthorityIdentity: plan.Authorities.Management, TokenFile: authorityToken, CAFile: caPath},
		Plan:      plan, Projection: runnerEnablementPlan(plan), Clock: func() time.Time { return time.Date(2026, 8, 16, 21, 0, 0, 0, time.UTC) },
	}
}

func runnerEnablementPlan(plan stageplan.Binding) submission.EnablementPlan {
	object := submission.Object{
		Identity: projection.ResourceIdentity{APIVersion: "addons.cluster.x-k8s.io/v1alpha1", Kind: "HelmChartProxy", Namespace: plan.ContractIdentity.Namespace, Name: plan.ContractIdentity.Name + "-cilium"},
		Digest:   runnerStageSHA("5"), CollectionPath: "/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/" + plan.ContractIdentity.Namespace + "/helmchartproxies",
		ObjectPath: "/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/" + plan.ContractIdentity.Namespace + "/helmchartproxies/" + plan.ContractIdentity.Name + "-cilium",
		Raw:        json.RawMessage(`{"apiVersion":"addons.cluster.x-k8s.io/v1alpha1","kind":"HelmChartProxy"}`),
	}
	return submission.EnablementPlan{
		Format: submission.EnablementPlanFormat, IntentRevision: plan.IntentRevision, EnablementRevision: plan.EnablementRevision, ExecutionFixture: plan.ExecutionFixture,
		ArtifactDigest: runnerStageSHA("d"), MutationAllowed: false,
		Management: submission.Plane{Identity: plan.Authorities.Management, Role: "enablement-desired-state-writer", Objects: []submission.Object{object}},
	}
}
