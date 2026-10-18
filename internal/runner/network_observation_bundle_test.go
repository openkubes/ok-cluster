package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func TestNetworkObservationStageBundleLoadsExactReadOnlyCursor(t *testing.T) {
	bundle, err := LoadNetworkObservationStageBundle(networkObservationBundleConfig(t, true))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := bundle.Decision()
	if err != nil || decision.StageID != "network-observation" || decision.Authority != "workload" || decision.RequiresAuthorization || decision.Operation != "" {
		t.Fatalf("unexpected network bundle decision: %#v %v", decision, err)
	}
	if _, err := (VerifiedNetworkObservationStageBundle{}).Decision(); err == nil {
		t.Fatal("unverified network bundle exposed a decision")
	}
}

func TestNetworkObservationStageBundleRejectsWrongStageOrMissingCorrelation(t *testing.T) {
	if _, err := LoadNetworkObservationStageBundle(lifecycleObservationBundleConfig(t, true)); err == nil || !strings.Contains(err.Error(), "does not select") {
		t.Fatalf("lifecycle observation cursor was accepted: %v", err)
	}
	if _, err := LoadNetworkObservationStageBundle(networkObservationBundleConfig(t, false)); err == nil || !strings.Contains(err.Error(), "durable target") {
		t.Fatalf("history without target correlation was accepted: %v", err)
	}
}

func TestNetworkObservationStageBundleOpensWithoutClusterContact(t *testing.T) {
	bundle, err := LoadNetworkObservationStageBundle(networkObservationBundleConfig(t, true))
	if err != nil {
		t.Fatal(err)
	}
	runtime := networkObservationRuntime(t, bundle, "ledger-token", "management-token", "workload-token", "cluster-runtime-uid-147")
	opened, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.verified {
		t.Fatal("opened network observation stage is not verified")
	}
	if _, err := (OpenedNetworkObservationStage{}).Run(context.Background()); err == nil {
		t.Fatal("unopened network observation stage could run")
	}
}

func TestNetworkObservationStageBundleRequiresDistinctCorrelatedInputs(t *testing.T) {
	bundle, err := LoadNetworkObservationStageBundle(networkObservationBundleConfig(t, true))
	if err != nil {
		t.Fatal(err)
	}
	for name, runtime := range map[string]NetworkObservationStageRuntimeConfig{
		"shared ledger management token": networkObservationRuntime(t, bundle, "shared-token", "shared-token", "workload-token", "cluster-runtime-uid-147"),
		"shared ledger workload token":   networkObservationRuntime(t, bundle, "shared-token", "management-token", "shared-token", "cluster-runtime-uid-147"),
		"replacement target":             networkObservationRuntime(t, bundle, "ledger-token", "management-token", "workload-token", "replacement-runtime-uid"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := bundle.Open(runtime); err == nil {
				t.Fatal("unsafe network runtime composition was accepted")
			}
		})
	}
	runtime := networkObservationRuntime(t, bundle, "ledger-token", "management-token", "workload-token", "cluster-runtime-uid-147")
	runtime.Management.AuthorityIdentity = "foreign-management"
	if _, err := bundle.Open(runtime); err == nil {
		t.Fatal("foreign management authority was accepted")
	}
	if _, err := (VerifiedNetworkObservationStageBundle{}).Open(runtime); err == nil {
		t.Fatal("unverified bundle opened network credentials")
	}
}

func TestNetworkObservationRejectsForeignProfileBeforeCredentialReads(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		name := "ordinary"
		if recovery {
			name = "recovery"
		}
		t.Run(name, func(t *testing.T) {
			config := networkObservationBundleConfig(t, true)
			if recovery {
				config = networkRecoveryFixture(t)
			}
			bundle, err := LoadNetworkObservationStageBundle(config)
			if recovery {
				if err == nil || !strings.Contains(err.Error(), "recovery execution is disabled") {
					t.Fatalf("recovery opened capabilities: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			runtime := networkObservationRuntime(t, bundle, "ledger-token", "management-token", "workload-token", "cluster-runtime-uid-147")
			foreign := networkStageProfile(bundle.plan)
			foreign.ExpectedNodeCount++
			runtime.ExpectedNetworkProfileDigest, err = observation.NetworkProfileDigest(foreign)
			if err != nil {
				t.Fatal(err)
			}
			writePlatformJSON(t, runtime.NetworkProfilePath, foreign)
			// Even a valid file/digest pair with the correct R/E must not choose
			// a profile outside the plan. Missing credentials prove gate ordering.
			runtime.Workload.Path = filepath.Join(t.TempDir(), "absent-binding")
			runtime.Ledger.TokenFile = filepath.Join(t.TempDir(), "absent-token")
			if _, err := bundle.Open(runtime); err == nil || !strings.Contains(err.Error(), "exact plan-bound network profile") {
				t.Fatalf("foreign profile reached credential loading: %v", err)
			}
		})
	}
}

func networkObservationBundleConfig(t *testing.T, withTargetDigest bool) StageResumeConfig {
	t.Helper()
	base := lifecycleObservationBundleConfig(t, withTargetDigest)
	plan, _, _, err := loadStageResumeWithPrefix(base)
	if err != nil {
		t.Fatal(err)
	}
	// Bind the real test profile, rather than relying on a synthetic digest
	// unrelated to the runtime input. Regenerate the source prefix under it.
	profileDigest, err := observation.NetworkProfileDigest(networkStageProfile(plan))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(base.PlanPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["stages"].([]any)[4].(map[string]any)["inputs"].([]any)[0].(map[string]any)["digest"] = profileDigest
	writePlatformJSON(t, base.PlanPath, doc)
	plan, err = stageplan.Load(base.PlanPath, base.PlanExpected)
	if err != nil {
		t.Fatal(err)
	}
	_, prefix, _ := networkObserverPrefixForPlan(t, plan, withTargetDigest)
	root := t.TempDir()
	base.Receipts = []StageReceiptSource{}
	for _, receipt := range prefix {
		raw, _ := receipt.Bytes()
		receiptDigest, _ := receipt.Digest()
		r, _ := receipt.Receipt()
		base.Receipts = append(base.Receipts, StageReceiptSource{Path: writeBundleFile(t, root, r.StageID+".json", raw), Digest: receiptDigest})
	}
	return base
}

func networkObservationRuntime(t *testing.T, bundle VerifiedNetworkObservationStageBundle, ledgerToken, managementToken, workloadToken, targetUID string) NetworkObservationStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	managementCA, workloadCA := testCA(t), testCA(t)
	paths := map[string]string{
		"management-ca":    filepath.Join(root, "management-ca.crt"),
		"workload-ca":      filepath.Join(root, "workload-ca.crt"),
		"ledger-token":     filepath.Join(root, "ledger-token"),
		"management-token": filepath.Join(root, "management-token"),
		"workload-token":   filepath.Join(root, "workload-token"),
		"binding":          filepath.Join(root, "workload-binding.json"),
		"profile":          filepath.Join(root, "network-profile.json"),
	}
	for path, content := range map[string][]byte{
		paths["management-ca"]: managementCA, paths["workload-ca"]: workloadCA,
		paths["ledger-token"]: []byte(ledgerToken), paths["management-token"]: []byte(managementToken), paths["workload-token"]: []byte(workloadToken),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	binding := WorkloadAuthorityBinding{
		Format: WorkloadAuthorityBindingFormat, IntentRevision: bundle.plan.IntentRevision,
		TargetClusterUID: targetUID, TargetIdentityScheme: "capi-cluster-uid/v1",
		Endpoint: "https://192.0.2.20:6443", CABundleDigest: digest.SHA256(workloadCA),
	}
	writePlatformJSON(t, paths["binding"], binding)
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	profile := networkStageProfile(bundle.plan)
	writePlatformJSON(t, paths["profile"], profile)
	profileDigest, err := observation.NetworkProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	return NetworkObservationStageRuntimeConfig{
		Ledger: KubernetesLedgerConfig{
			Endpoint: "https://192.0.2.10:6443", Namespace: "openkubes-execution-system",
			TokenFile: paths["ledger-token"], CAFile: paths["management-ca"],
		},
		Management: KubernetesAuthorityConfig{
			Endpoint: "https://192.0.2.10:6443", AuthorityIdentity: bundle.plan.Authorities.Management,
			TokenFile: paths["management-token"], CAFile: paths["management-ca"],
		},
		Workload: WorkloadAuthorityFileResolverConfig{
			Path: paths["binding"], ExpectedBindingDigest: bindingDigest,
			TokenFile: paths["workload-token"], CAFile: paths["workload-ca"],
		},
		NetworkProfilePath: paths["profile"], ExpectedNetworkProfileDigest: profileDigest,
		PollInterval: time.Second, PollTimeout: time.Minute, Clock: time.Now,
		Wait: func(context.Context, time.Duration) error { return nil },
	}
}
