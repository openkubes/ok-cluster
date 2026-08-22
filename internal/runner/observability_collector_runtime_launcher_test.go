package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanObservabilityCollectorRuntimeInstallationBindsExactOrder(t *testing.T) {
	packaged := observabilityCollectorRuntimeLauncherPackage(t)
	plan, err := PlanObservabilityCollectorRuntimeInstallation(packaged)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Format != ObservabilityCollectorRuntimeInstallationPlanFormat || plan.State != "VERIFIED" ||
		plan.RunID != "ok147-evidence-collector-01" || plan.Authority != plan.TargetIdentityDigest ||
		!stageReceiptPrefixDigestPattern.MatchString(plan.Authority) || plan.MutationAllowed || len(plan.Prerequisites) != 2 || len(plan.Creates) != 4 {
		t.Fatalf("unexpected collector installation plan: %#v", plan)
	}
	for index, kind := range []string{"Secret", "Service", "NetworkPolicy", "Job"} {
		create := plan.Creates[index]
		if create.Order != index+1 || create.Kind != kind || create.Namespace != submissionStageInputNamespace ||
			create.PreflightMethod != http.MethodGet || create.CreateMethod != http.MethodPost || create.ObjectPath == "" ||
			create.CollectionPath == "" || !stageReceiptPrefixDigestPattern.MatchString(create.ObjectDigest) {
			t.Fatalf("create %d differs: %#v", index, create)
		}
	}
	public, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"bearer", "token", "certificate", "/private/", "endpoint"} {
		if strings.Contains(strings.ToLower(string(public)), forbidden) {
			t.Fatalf("collector installation plan exposed %q", forbidden)
		}
	}
}

func TestPlanObservabilityCollectorRuntimeInstallationFailsClosed(t *testing.T) {
	packaged := observabilityCollectorRuntimeLauncherPackage(t)
	for name, mutate := range map[string]func(*VerifiedObservabilityCollectorRuntimePackage){
		"raw":       func(value *VerifiedObservabilityCollectorRuntimePackage) { value.raw[0] ^= 0xff },
		"inventory": func(value *VerifiedObservabilityCollectorRuntimePackage) { value.receipt.ObjectKinds[1] = "ConfigMap" },
		"identity": func(value *VerifiedObservabilityCollectorRuntimePackage) {
			value.receipt.RuntimeBindingDigest = runnerStageSHA("f")
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := packaged
			candidate.raw = append([]byte(nil), packaged.raw...)
			candidate.receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
			mutate(&candidate)
			if _, err := PlanObservabilityCollectorRuntimeInstallation(candidate); err == nil {
				t.Fatal("changed collector package produced an installation plan")
			}
		})
	}
}

func TestLoadObservabilityCollectorRuntimePackageRequiresPrivateExactFiles(t *testing.T) {
	packaged := observabilityCollectorRuntimeLauncherPackage(t)
	raw, err := packaged.PrivateBytes()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	packagePath, receiptPath := filepath.Join(directory, "collector-private.yaml"), filepath.Join(directory, "receipt.json")
	if err := os.WriteFile(packagePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, receiptRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadObservabilityCollectorRuntimePackage(ObservabilityCollectorRuntimePackageFileConfig{
		PackagePath: packagePath, ReceiptPath: receiptPath, ExpectedReceiptDigest: digest.SHA256(receiptRaw),
	})
	if err != nil {
		t.Fatal(err)
	}
	loadedReceipt, err := loaded.Receipt()
	if err != nil || loadedReceipt.PackageDigest != receipt.PackageDigest {
		t.Fatalf("loaded collector package differs: %#v %v", loadedReceipt, err)
	}
	if err := os.Chmod(packagePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadObservabilityCollectorRuntimePackage(ObservabilityCollectorRuntimePackageFileConfig{
		PackagePath: packagePath, ReceiptPath: receiptPath, ExpectedReceiptDigest: digest.SHA256(receiptRaw),
	}); err == nil {
		t.Fatal("publicly readable collector package was accepted")
	}
}

func TestObservabilityCollectorRuntimeLauncherPreflightsThenCreates(t *testing.T) {
	packaged := observabilityCollectorRuntimeLauncherPackage(t)
	api := newSubmissionStageInstallerAPI(t)
	seedObservabilityCollectorRuntimePrerequisites(api)
	launcher := newObservabilityCollectorRuntimeLauncher(t, packaged, api.client())
	receipt, err := launcher.Launch(context.Background())
	if err != nil || receipt.State != "ACTIVATED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 4 {
		t.Fatalf("collector launch failed: %#v %v", receipt, err)
	}
	plan, _ := PlanObservabilityCollectorRuntimeInstallation(packaged)
	if receipt.Format != ObservabilityCollectorRuntimeLaunchReceiptFormat || receipt.PackageDigest != plan.PackageDigest ||
		receipt.TargetIdentityDigest != plan.TargetIdentityDigest || receipt.Authority != plan.Authority {
		t.Fatalf("collector launch identity differs: %#v", receipt)
	}
	if len(api.requests) != 10 {
		t.Fatalf("requests=%d, want two prerequisite GETs, four absence GETs and four POSTs: %#v", len(api.requests), api.requests)
	}
	for index, create := range plan.Creates {
		preflight, submission := api.requests[index+2], api.requests[index+6]
		if preflight.method != http.MethodGet || preflight.path != create.ObjectPath || len(preflight.body) != 0 {
			t.Fatalf("preflight %d differs: %#v", index, preflight)
		}
		if submission.method != http.MethodPost || submission.path != create.CollectionPath || digest.SHA256(submission.body) != create.ObjectDigest {
			t.Fatalf("submission %d differs: %#v", index, submission)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(public, []byte("short-lived-installer-token")) || bytes.Contains(public, []byte("created-stage-uid")) {
		t.Fatal("collector launch receipt disclosed credential or raw runtime identity")
	}
}

func TestObservabilityCollectorRuntimeLauncherStopsZeroWriteOnExistingObject(t *testing.T) {
	packaged := observabilityCollectorRuntimeLauncherPackage(t)
	api := newSubmissionStageInstallerAPI(t)
	seedObservabilityCollectorRuntimePrerequisites(api)
	plan, _ := PlanObservabilityCollectorRuntimeInstallation(packaged)
	api.objects[plan.Creates[1].ObjectPath] = map[string]any{"apiVersion": "v1", "kind": "Service"}
	launcher := newObservabilityCollectorRuntimeLauncher(t, packaged, api.client())
	receipt, err := launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 {
		t.Fatalf("existing collector object did not stop zero-write: %#v posts=%d err=%v", receipt, api.posts, err)
	}
}

func TestObservabilityCollectorRuntimeLauncherPreservesPartialAndCannotRetry(t *testing.T) {
	packaged := observabilityCollectorRuntimeLauncherPackage(t)
	api := newSubmissionStageInstallerAPI(t)
	seedObservabilityCollectorRuntimePrerequisites(api)
	api.failPost = 3
	launcher := newObservabilityCollectorRuntimeLauncher(t, packaged, api.client())
	receipt, err := launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED" ||
		len(receipt.Results) != 2 || receipt.Results[0].Kind != "Secret" || receipt.Results[1].Kind != "Service" {
		t.Fatalf("collector partial prefix differs: %#v %v", receipt, err)
	}
	requestCount := len(api.requests)
	retry, retryErr := launcher.Launch(context.Background())
	if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || retry.MutationState != "NOT_ATTEMPTED" || len(api.requests) != requestCount {
		t.Fatalf("single-use collector boundary failed: %#v requests=%d/%d err=%v", retry, len(api.requests), requestCount, retryErr)
	}
}

func observabilityCollectorRuntimeLauncherPackage(t *testing.T) VerifiedObservabilityCollectorRuntimePackage {
	t.Helper()
	packaged, err := BuildObservabilityCollectorRuntimePackage(observabilityCollectorRuntimePackageFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	return packaged
}

func newObservabilityCollectorRuntimeLauncher(t *testing.T, packaged VerifiedObservabilityCollectorRuntimePackage, client *http.Client) *KubernetesObservabilityCollectorRuntimeLauncher {
	t.Helper()
	plan, err := PlanObservabilityCollectorRuntimeInstallation(packaged)
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := newKubernetesObservabilityCollectorRuntimeLauncher(submissionStageInstallerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token", AuthorityIdentity: plan.Authority, Client: client,
	}, packaged)
	if err != nil {
		t.Fatal(err)
	}
	return launcher
}

func seedObservabilityCollectorRuntimePrerequisites(api *submissionStageInstallerAPI) {
	api.objects["/api/v1/namespaces/openkubes-execution-system"] = map[string]any{
		"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "openkubes-execution-system"},
	}
	api.objects["/api/v1/namespaces/openkubes-execution-system/serviceaccounts/ok147-contract-executor-runtime"] = map[string]any{
		"apiVersion": "v1", "kind": "ServiceAccount", "automountServiceAccountToken": false,
		"metadata": map[string]any{"name": "ok147-contract-executor-runtime", "namespace": "openkubes-execution-system", "labels": map[string]any{
			"app.kubernetes.io/name": "ok-cluster-contract-executor", "openkubes.io/runtime-boundary": "submission-stage",
		}},
	}
}
