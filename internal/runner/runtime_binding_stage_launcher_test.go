package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestRuntimeBindingStageLauncherPreflightsThenCreatesJobLast(t *testing.T) {
	api := newSubmissionStageLauncherAPI(t)
	opened := newRuntimeBindingStageLauncher(t, api, time.Date(2026, 8, 16, 12, 2, 0, 0, time.UTC))
	receipt, err := opened.Launch(context.Background())
	if err != nil || receipt.State != "LAUNCHED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 7 {
		t.Fatalf("runtime binding launch failed: %#v %v", receipt, err)
	}
	plan, _ := PlanRuntimeBindingStageLaunch(opened.material.packaged, opened.material.credentials, opened.material.runtime)
	if len(api.requests) != 14 || api.posts != 7 {
		t.Fatalf("requests=%d posts=%d, want seven GETs then seven POSTs", len(api.requests), api.posts)
	}
	for index := 0; index < 7; index++ {
		preflight, create := api.requests[index], api.requests[index+7]
		if preflight.method != "GET" || preflight.path != plan.Preflights[index].ObjectPath || create.method != "POST" || create.path != plan.Creates[index].CollectionPath || digest.SHA256(create.body) != plan.Creates[index].ObjectDigest {
			t.Fatalf("request order %d differs: %#v %#v", index+1, preflight, create)
		}
		if receipt.Results[index].Order != index+1 || receipt.Results[index].Kind != plan.Creates[index].Kind || receipt.Results[index].ObjectState != "CREATED" {
			t.Fatalf("result %d differs: %#v", index+1, receipt.Results[index])
		}
	}
	if plan.Creates[6].Kind != "Job" {
		t.Fatal("runtime binding Job was not created last")
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte(opened.token), opened.material.credentials.objects[0].raw, opened.material.credentials.objects[1].raw, opened.material.credentials.objects[2].raw, []byte("created-uid")} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("runtime binding launch receipt exposed private content")
		}
	}
	requests := len(api.requests)
	retry, retryErr := opened.Launch(context.Background())
	if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || len(api.requests) != requests {
		t.Fatalf("single-use runtime binding launcher retried: %#v %v", retry, retryErr)
	}
}

func TestRuntimeBindingStageLauncherAcceptsOnlyExactCompleteDuplicate(t *testing.T) {
	api := newSubmissionStageLauncherAPI(t)
	now := time.Date(2026, 8, 16, 12, 2, 0, 0, time.UTC)
	first := newRuntimeBindingStageLauncher(t, api, now)
	if receipt, err := first.Launch(context.Background()); err != nil || receipt.State != "LAUNCHED" {
		t.Fatalf("first runtime binding launch failed: %#v %v", receipt, err)
	}
	requests := len(api.requests)
	duplicate := &OpenedRuntimeBindingStageLaunch{
		mu: sync.Mutex{}, material: first.material, endpoint: first.endpoint, token: first.token,
		client: first.client, clock: first.clock, validUntil: first.validUntil,
		receipt: first.receipt, verified: true,
	}
	receipt, err := duplicate.Launch(context.Background())
	if err != nil || receipt.State != "ALREADY_LAUNCHED" || receipt.MutationState != "NOT_ATTEMPTED" || len(receipt.Results) != 7 || api.posts != 7 || len(api.requests) != requests+7 {
		t.Fatalf("exact runtime binding duplicate was not idempotent: %#v %v", receipt, err)
	}

	api = newSubmissionStageLauncherAPI(t)
	partial := newRuntimeBindingStageLauncher(t, api, now)
	_, objects, _ := prepareRuntimeBindingStageInstallation(partial.material.packaged)
	existing := decodeCapabilityJSONForTest(t, objects[0].raw)
	metadata := existing["metadata"].(map[string]any)
	metadata["uid"], metadata["resourceVersion"] = "existing-input-uid", "9"
	plan, _ := PlanRuntimeBindingStageLaunch(partial.material.packaged, partial.material.credentials, partial.material.runtime)
	api.objects[plan.Preflights[1].ObjectPath] = existing
	receipt, err = partial.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 || len(api.requests) != 7 {
		t.Fatalf("partial runtime binding state reached mutation: %#v %v", receipt, err)
	}
}

func TestRuntimeBindingStageLauncherPreservesPartialPrefixAndStopsStaleLocally(t *testing.T) {
	api := newSubmissionStageLauncherAPI(t)
	api.failPost = 6
	opened := newRuntimeBindingStageLauncher(t, api, time.Date(2026, 8, 16, 12, 2, 0, 0, time.UTC))
	receipt, err := opened.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED_UNKNOWN" || len(receipt.Results) != 5 || api.posts != 6 {
		t.Fatalf("partial runtime binding prefix differs: %#v %v", receipt, err)
	}

	api = newSubmissionStageLauncherAPI(t)
	stale := newRuntimeBindingStageLauncher(t, api, time.Date(2026, 8, 16, 12, 16, 0, 0, time.UTC))
	receipt, err = stale.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || len(api.requests) != 0 {
		t.Fatalf("stale runtime binding candidate reached API: %#v %v", receipt, err)
	}
}

func newRuntimeBindingStageLauncher(t *testing.T, api *submissionStageLauncherAPI, now time.Time) *OpenedRuntimeBindingStageLaunch {
	t.Helper()
	config, _ := runtimeBindingStageLaunchMaterialConfig(t)
	config.Candidate.AuthorityEndpoint = "https://192.0.2.10:6443"
	config.Candidate.CABundleDigest = prefixSHA("7")
	config.Candidate.InstallerTokenDigest = digest.SHA256([]byte("short-lived-installer-token"))
	material, err := BuildRuntimeBindingStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := url.Parse(config.Candidate.AuthorityEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	validUntil, err := time.Parse(time.RFC3339, material.receipt.ValidUntil)
	if err != nil {
		t.Fatal(err)
	}
	return &OpenedRuntimeBindingStageLaunch{
		material: material, endpoint: endpoint, token: "short-lived-installer-token", client: api.client(),
		clock: func() time.Time { return now }, validUntil: validUntil,
		receipt: RuntimeBindingStageLaunchOpenReceipt{
			Format: RuntimeBindingStageLaunchOpenReceiptFormat, State: "OPENED", StageID: "runtime-binding",
			Authority: "ok-mgmt", CandidateDigest: material.receipt.CandidateDigest,
			ValidUntil: material.receipt.ValidUntil, MutationAllowed: false,
		},
		verified: true,
	}
}
