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

func TestNetworkObservationStageLauncherPreflightsThenCreatesJobLast(t *testing.T) {
	stage, credentials, runtime, tokens := networkObservationStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	launcher := newNetworkObservationStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
	receipt, err := launcher.Launch(context.Background())
	if err != nil || receipt.State != "LAUNCHED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 7 {
		t.Fatalf("network observation launch failed: %#v %v", receipt, err)
	}
	if len(api.requests) != 14 || api.posts != 7 {
		t.Fatalf("requests=%d posts=%d, want seven GETs then seven POSTs", len(api.requests), api.posts)
	}
	for index := 0; index < 7; index++ {
		preflight, create := api.requests[index], api.requests[index+7]
		if preflight.method != "GET" || preflight.path != launcher.plan.Preflights[index].ObjectPath || create.method != "POST" || create.path != launcher.plan.Creates[index].CollectionPath || digest.SHA256(create.body) != launcher.plan.Creates[index].ObjectDigest {
			t.Fatalf("request order %d differs: %#v %#v", index+1, preflight, create)
		}
		if receipt.Results[index].Order != index+1 || receipt.Results[index].Kind != launcher.plan.Creates[index].Kind || receipt.Results[index].ObjectState != "CREATED" {
			t.Fatalf("result %d differs: %#v", index+1, receipt.Results[index])
		}
	}
	if launcher.plan.Creates[6].Kind != "Job" || launcher.plan.Creates[3].Kind != "Secret" || launcher.plan.Creates[4].Kind != "Secret" || launcher.plan.Creates[5].Kind != "Secret" {
		t.Fatalf("Job was not held behind three credentials: %#v", launcher.plan.Creates)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append(tokens, credentials.objects[0].raw, credentials.objects[1].raw, credentials.objects[2].raw, []byte("short-lived-installer-token"), []byte("created-uid")) {
		if bytes.Contains(public, forbidden) {
			t.Fatal("network observation receipt exposed private content")
		}
	}
	requests := len(api.requests)
	retry, retryErr := launcher.Launch(context.Background())
	if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || len(api.requests) != requests {
		t.Fatalf("single-use network launcher retried: %#v %v", retry, retryErr)
	}
}

func TestNetworkObservationStageLauncherAcceptsOnlyExactCompleteDuplicate(t *testing.T) {
	stage, credentials, runtime, _ := networkObservationStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	now := time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC)
	first := newNetworkObservationStageLauncher(t, stage, credentials, runtime, api, now)
	if receipt, err := first.Launch(context.Background()); err != nil || receipt.State != "LAUNCHED" {
		t.Fatalf("first network launch failed: %#v %v", receipt, err)
	}
	requests := len(api.requests)
	duplicate := newNetworkObservationStageLauncher(t, stage, credentials, runtime, api, now)
	receipt, err := duplicate.Launch(context.Background())
	if err != nil || receipt.State != "ALREADY_LAUNCHED" || receipt.MutationState != "NOT_ATTEMPTED" || len(receipt.Results) != 7 || api.posts != 7 || len(api.requests) != requests+7 {
		t.Fatalf("exact network duplicate was not idempotent: %#v %v", receipt, err)
	}

	stage, credentials, runtime, _ = networkObservationStageLaunchFixture(t)
	api = newSubmissionStageLauncherAPI(t)
	partial := newNetworkObservationStageLauncher(t, stage, credentials, runtime, api, now)
	existing := decodeCapabilityJSONForTest(t, partial.objects[0].raw)
	metadata := existing["metadata"].(map[string]any)
	metadata["uid"], metadata["resourceVersion"] = "existing-input-uid", "9"
	api.objects[partial.plan.Preflights[1].ObjectPath] = existing
	receipt, err = partial.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 || len(api.requests) != 7 {
		t.Fatalf("partial network state reached mutation: %#v %v", receipt, err)
	}
}

func TestNetworkObservationStageLauncherPreservesPartialPrefixAndStopsStaleLocally(t *testing.T) {
	stage, credentials, runtime, _ := networkObservationStageLaunchFixture(t)
	api := newSubmissionStageLauncherAPI(t)
	api.failPost = 6
	launcher := newNetworkObservationStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
	receipt, err := launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED_UNKNOWN" || len(receipt.Results) != 5 || api.posts != 6 {
		t.Fatalf("partial network prefix differs: %#v %v", receipt, err)
	}

	stage, credentials, runtime, _ = networkObservationStageLaunchFixture(t)
	api = newSubmissionStageLauncherAPI(t)
	stale := newNetworkObservationStageLauncher(t, stage, credentials, runtime, api, time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC))
	receipt, err = stale.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || len(api.requests) != 0 {
		t.Fatalf("stale network candidate reached API: %#v %v", receipt, err)
	}
}

func TestOpenNetworkObservationStageLauncherRequiresExactCandidate(t *testing.T) {
	stage, credentials, runtime, _ := networkObservationStageLaunchFixture(t)
	installerToken := []byte("installer-token-v1")
	ca := testCA(t)
	candidateConfig := submissionStageLaunchCandidateConfig()
	candidateConfig.CABundleDigest = digest.SHA256(ca)
	candidateConfig.InstallerTokenDigest = digest.SHA256(installerToken)
	candidate, err := PrepareNetworkObservationStageLaunchCandidate(candidateConfig, stage, credentials, runtime)
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
	config := NetworkObservationStageLauncherConfig{
		Authority: KubernetesAuthorityConfig{
			Endpoint: candidateConfig.AuthorityEndpoint, AuthorityIdentity: "ok-mgmt", TokenFile: tokenPath, CAFile: caPath, CABundleDigest: candidateConfig.CABundleDigest,
		},
		Clock:     func() time.Time { return time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC) },
		Candidate: candidate, ExpectedCandidateDigest: candidateReceipt.CandidateDigest,
	}
	launcher, err := OpenKubernetesNetworkObservationStageLauncher(config, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" {
		t.Fatalf("expired network candidate did not stop before API contact: %#v %v", receipt, err)
	}
	config.ExpectedCandidateDigest = digest.SHA256([]byte("foreign"))
	if _, err := OpenKubernetesNetworkObservationStageLauncher(config, stage, credentials, runtime); err == nil {
		t.Fatal("foreign network candidate digest accepted")
	}
}

func newNetworkObservationStageLauncher(t *testing.T, stage VerifiedNetworkObservationStagePackage, credentials VerifiedNetworkObservationStageCredentialPackage, runtime VerifiedNetworkObservationStageRuntimePrerequisite, api *submissionStageLauncherAPI, now time.Time) *KubernetesNetworkObservationStageLauncher {
	t.Helper()
	launcher, err := newKubernetesNetworkObservationStageLauncher(submissionStageLauncherClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-mgmt",
		Client: api.client(), Clock: func() time.Time { return now }, ValidUntil: time.Date(2026, 8, 16, 12, 15, 0, 0, time.UTC),
	}, stage, credentials, runtime)
	if err != nil {
		t.Fatal(err)
	}
	return launcher
}
