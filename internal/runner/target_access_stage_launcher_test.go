package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestTargetAccessStageLauncherPreflightsThenCreatesJobLast(t *testing.T) {
	stage, credentials, runtime, tokens := targetAccessStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	launcher := newTargetAccessStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 14, 1, 0, 0, time.UTC))
	receipt, err := launcher.Launch(context.Background())
	if err != nil || receipt.State != "LAUNCHED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 6 {
		t.Fatalf("target-access launch failed: %#v %v", receipt, err)
	}
	if len(api.requests) != 12 || api.posts != 6 {
		t.Fatalf("requests=%d posts=%d, want six GETs then six POSTs", len(api.requests), api.posts)
	}
	for index := 0; index < 6; index++ {
		preflight, create := api.requests[index], api.requests[index+6]
		if preflight.method != "GET" || preflight.path != launcher.plan.Preflights[index].ObjectPath || create.method != "POST" || create.path != launcher.plan.Creates[index].CollectionPath || digest.SHA256(create.body) != launcher.plan.Creates[index].ObjectDigest {
			t.Fatalf("request order %d differs: %#v %#v", index+1, preflight, create)
		}
		if receipt.Results[index].Order != index+1 || receipt.Results[index].Kind != launcher.plan.Creates[index].Kind || receipt.Results[index].ObjectState != "CREATED" {
			t.Fatalf("result %d differs: %#v", index+1, receipt.Results[index])
		}
	}
	if launcher.plan.Creates[5].Kind != "Job" || launcher.plan.Creates[3].Kind != "Secret" || launcher.plan.Creates[4].Kind != "Secret" {
		t.Fatalf("Job was not held behind both credentials: %#v", launcher.plan.Creates)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append(tokens, credentials.objects[0].raw, credentials.objects[1].raw, []byte("short-lived-installer-token"), []byte("created-uid")) {
		if bytes.Contains(public, forbidden) {
			t.Fatal("target-access receipt exposed private content")
		}
	}
	requests := len(api.requests)
	retry, retryErr := launcher.Launch(context.Background())
	if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || len(api.requests) != requests {
		t.Fatalf("single-use launcher retried: %#v %v", retry, retryErr)
	}
}

func TestTargetAccessStageLauncherAcceptsOnlyExactCompleteDuplicate(t *testing.T) {
	stage, credentials, runtime, _ := targetAccessStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	now := time.Date(2026, 8, 16, 14, 1, 0, 0, time.UTC)
	first := newTargetAccessStageLauncher(t, stage, credentials, runtime, api, now)
	if receipt, err := first.Launch(context.Background()); err != nil || receipt.State != "LAUNCHED" {
		t.Fatalf("first launch failed: %#v %v", receipt, err)
	}
	requests := len(api.requests)
	duplicate := newTargetAccessStageLauncher(t, stage, credentials, runtime, api, now)
	receipt, err := duplicate.Launch(context.Background())
	if err != nil || receipt.State != "ALREADY_LAUNCHED" || receipt.MutationState != "NOT_ATTEMPTED" || len(receipt.Results) != 6 || api.posts != 6 || len(api.requests) != requests+6 {
		t.Fatalf("exact duplicate was not idempotent: %#v %v", receipt, err)
	}

	stage, credentials, runtime, _ = targetAccessStageLaunchFixture(t)
	api = newSubmissionStageLauncherAPI(t)
	partial := newTargetAccessStageLauncher(t, stage, credentials, runtime, api, now)
	existing := decodeCapabilityJSONForTest(t, partial.objects[0].raw)
	metadata := existing["metadata"].(map[string]any)
	metadata["uid"], metadata["resourceVersion"] = "existing-input-uid", "9"
	api.objects[partial.plan.Preflights[1].ObjectPath] = existing
	receipt, err = partial.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 || len(api.requests) != 6 {
		t.Fatalf("partial target-access state reached mutation: %#v %v", receipt, err)
	}
}

func TestTargetAccessStageLauncherReusesOnlyExactSharedRuntime(t *testing.T) {
	stage, credentials, runtime, _ := targetAccessStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	runtimeObject := decodeCapabilityJSONForTest(t, runtime.raw)
	metadata := runtimeObject["metadata"].(map[string]any)
	metadata["uid"], metadata["resourceVersion"] = "runtime-existing-uid", "7"
	api.objects[stageRuntimeObjectPath] = runtimeObject
	launcher := newTargetAccessStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 14, 1, 0, 0, time.UTC))
	receipt, err := launcher.Launch(context.Background())
	if err != nil || receipt.State != "LAUNCHED" || len(receipt.Results) != 6 || receipt.Results[0].ObjectState != "EXISTING_VERIFIED" || api.posts != 5 || len(api.requests) != 11 {
		t.Fatalf("existing shared runtime was not reused exactly: %#v requests=%d posts=%d err=%v", receipt, len(api.requests), api.posts, err)
	}

	stage, credentials, runtime, _ = targetAccessStageLaunchFixture(t)
	api = newSubmissionStageLauncherAPI(t)
	runtimeObject = decodeCapabilityJSONForTest(t, runtime.raw)
	runtimeObject["automountServiceAccountToken"] = true
	metadata = runtimeObject["metadata"].(map[string]any)
	metadata["uid"], metadata["resourceVersion"] = "runtime-existing-uid", "7"
	api.objects[stageRuntimeObjectPath] = runtimeObject
	launcher = newTargetAccessStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 14, 1, 0, 0, time.UTC))
	receipt, err = launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || api.posts != 0 || len(api.requests) != 1 {
		t.Fatalf("changed shared runtime reached create phase: %#v requests=%d posts=%d err=%v", receipt, len(api.requests), api.posts, err)
	}
}

func TestTargetAccessStageLauncherPreservesPartialPrefixAndStopsStaleLocally(t *testing.T) {
	stage, credentials, runtime, _ := targetAccessStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	api.failPost = 5
	launcher := newTargetAccessStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 14, 1, 0, 0, time.UTC))
	receipt, err := launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED_UNKNOWN" || len(receipt.Results) != 4 || api.posts != 5 {
		t.Fatalf("partial prefix differs: %#v %v", receipt, err)
	}

	stage, credentials, runtime, _ = targetAccessStageLaunchFixture(t)
	api = newSubmissionStageLauncherAPI(t)
	stale := newTargetAccessStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 14, 16, 0, 0, time.UTC))
	receipt, err = stale.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || len(api.requests) != 0 {
		t.Fatalf("stale target-access candidate reached API: %#v %v", receipt, err)
	}
}

func TestOpenTargetAccessStageLauncherRequiresExactCandidate(t *testing.T) {
	stage, credentials, runtime, _ := targetAccessStageLaunchFixture(t)
	installerToken := []byte("installer-token-v1")
	ca := testCA(t)
	candidateConfig := targetAccessLaunchCandidateConfig()
	candidateConfig.CABundleDigest = digest.SHA256(ca)
	candidateConfig.InstallerTokenDigest = digest.SHA256(installerToken)
	candidate, err := PrepareTargetAccessStageLaunchCandidate(candidateConfig, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	candidateReceipt, _ := candidate.Receipt()
	root := t.TempDir()
	tokenPath, caPath := filepath.Join(root, "installer-token"), filepath.Join(root, "ca.crt")
	if err := os.WriteFile(tokenPath, installerToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	config := TargetAccessStageLauncherConfig{
		Authority: KubernetesAuthorityConfig{
			Endpoint: candidateConfig.AuthorityEndpoint, AuthorityIdentity: "ok-shared", TokenFile: tokenPath, CAFile: caPath, CABundleDigest: candidateConfig.CABundleDigest,
		},
		Clock:     func() time.Time { return time.Date(2026, 8, 16, 14, 16, 0, 0, time.UTC) },
		Candidate: candidate, ExpectedCandidateDigest: candidateReceipt.CandidateDigest,
	}
	launcher, err := OpenKubernetesTargetAccessStageLauncher(config, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" {
		t.Fatalf("expired candidate did not stop before API contact: %#v %v", receipt, err)
	}
	config.ExpectedCandidateDigest = digest.SHA256([]byte("foreign"))
	if _, err := OpenKubernetesTargetAccessStageLauncher(config, stage, credentials, runtime); err == nil {
		t.Fatal("foreign candidate digest accepted")
	}
}

func newTargetAccessStageLauncher(t *testing.T, stage VerifiedTargetAccessStagePackage, credentials VerifiedTargetAccessStageCredentialPackage, runtime VerifiedTargetAccessStageRuntimePrerequisite, api *submissionStageLauncherAPI, now time.Time) *KubernetesTargetAccessStageLauncher {
	t.Helper()
	launcher, err := newKubernetesTargetAccessStageLauncher(submissionStageLauncherClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-shared",
		Client: api.client(), Clock: func() time.Time { return now }, ValidUntil: time.Date(2026, 8, 16, 14, 15, 0, 0, time.UTC),
	}, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	return launcher
}
