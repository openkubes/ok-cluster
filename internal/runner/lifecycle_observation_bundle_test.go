package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestLifecycleObservationStageBundleLoadsExactReadOnlyCursor(t *testing.T) {
	config := lifecycleObservationBundleConfig(t, true)
	bundle, err := LoadLifecycleObservationStageBundle(config)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := bundle.Decision()
	if err != nil || decision.StageID != "lifecycle-observation" || decision.RequiresAuthorization || decision.Operation != "" {
		t.Fatalf("unexpected lifecycle bundle decision: %#v %v", decision, err)
	}
	if _, err := (VerifiedLifecycleObservationStageBundle{}).Decision(); err == nil {
		t.Fatal("unverified lifecycle bundle exposed a decision")
	}
}

func TestLifecycleObservationStageBundleRejectsWrongStageOrMissingCorrelation(t *testing.T) {
	providerOnly := submissionBundleFixture(t, true, "")
	if _, err := LoadLifecycleObservationStageBundle(StageResumeConfig{
		PlanPath: providerOnly.config.PlanPath, PlanExpected: providerOnly.config.PlanExpected, Receipts: providerOnly.config.Receipts,
	}); err == nil || !strings.Contains(err.Error(), "does not select") {
		t.Fatalf("mutating lifecycle cursor was accepted: %v", err)
	}
	if _, err := LoadLifecycleObservationStageBundle(lifecycleObservationBundleConfig(t, false)); err == nil || !strings.Contains(err.Error(), "durable target") {
		t.Fatalf("lifecycle receipt without runtime correlation was accepted: %v", err)
	}
}

func TestLifecycleObservationStageBundleOpensWithoutClusterContact(t *testing.T) {
	bundle, err := LoadLifecycleObservationStageBundle(lifecycleObservationBundleConfig(t, true))
	if err != nil {
		t.Fatal(err)
	}
	runtime := lifecycleObservationRuntime(t, "ledger-token", "management-observer-token")
	opened, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.verified {
		t.Fatal("opened lifecycle stage is not verified")
	}
	if _, err := (OpenedLifecycleObservationStage{}).Run(context.Background()); err == nil {
		t.Fatal("unopened lifecycle stage could run")
	}
}

func TestLifecycleObservationStageBundleRequiresDistinctBoundedCredentials(t *testing.T) {
	bundle, err := LoadLifecycleObservationStageBundle(lifecycleObservationBundleConfig(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Open(lifecycleObservationRuntime(t, "shared-token", "shared-token")); err == nil {
		t.Fatal("shared ledger and management observation credential was accepted")
	}
	runtime := lifecycleObservationRuntime(t, "ledger-token", "management-observer-token")
	runtime.Management.AuthorityIdentity = "foreign-management"
	if _, err := bundle.Open(runtime); err == nil {
		t.Fatal("foreign management observation authority was accepted")
	}
	if _, err := (VerifiedLifecycleObservationStageBundle{}).Open(runtime); err == nil {
		t.Fatal("unverified lifecycle bundle opened runtime credentials")
	}
}

func lifecycleObservationBundleConfig(t *testing.T, withTargetDigest bool) StageResumeConfig {
	t.Helper()
	fixture := submissionBundleFixture(t, true, "")
	provider, err := stagereceipt.Load(fixture.config.Receipts[0].Path, fixture.config.Receipts[0].Digest, fixture.plan, []stagereceipt.Verified{})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 16, 20, 0, 0, 0, time.UTC)
	var lifecycle stagereceipt.Verified
	if withTargetDigest {
		lifecycle, err = stagereceipt.NewWithTargetClusterUIDDigest(
			fixture.plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, "SUCCEEDED", "ATTEMPTED",
			bundleSHA("1"), bundleSHA("2"), digest.SHA256([]byte("cluster-runtime-uid-147")), at,
		)
	} else {
		lifecycle, err = stagereceipt.New(
			fixture.plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, "SUCCEEDED", "ATTEMPTED",
			bundleSHA("1"), bundleSHA("2"), at,
		)
	}
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := lifecycle.Bytes()
	receiptDigest, _ := lifecycle.Digest()
	lifecycleSource := StageReceiptSource{Path: writeBundleFile(t, t.TempDir(), "cluster-lifecycle.json", raw), Digest: receiptDigest}
	return StageResumeConfig{
		PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected,
		Receipts: append(append([]StageReceiptSource{}, fixture.config.Receipts...), lifecycleSource),
	}
}

func lifecycleObservationRuntime(t *testing.T, ledgerToken, managementToken string) LifecycleObservationStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	caPath := filepath.Join(root, "ca.crt")
	ledgerTokenPath := filepath.Join(root, "ledger-token")
	managementTokenPath := filepath.Join(root, "management-token")
	for path, content := range map[string][]byte{
		caPath: testCA(t), ledgerTokenPath: []byte(ledgerToken), managementTokenPath: []byte(managementToken),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return LifecycleObservationStageRuntimeConfig{
		Ledger: KubernetesLedgerConfig{
			Endpoint: "https://192.0.2.10:6443", Namespace: "openkubes-execution-system", TokenFile: ledgerTokenPath, CAFile: caPath,
		},
		Management: KubernetesAuthorityConfig{
			Endpoint: "https://192.0.2.10:6443", AuthorityIdentity: "ok-mgmt", TokenFile: managementTokenPath, CAFile: caPath,
		},
		PollInterval: time.Second, PollTimeout: time.Minute, Clock: time.Now,
		Wait: func(context.Context, time.Duration) error { return nil },
	}
}
