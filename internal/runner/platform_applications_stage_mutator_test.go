package runner

import (
	"context"
	"testing"

	"github.com/openkubes/ok-cluster/internal/execution"
)

func TestPlatformApplicationsStageMutatorReturnsBoundedSuccess(t *testing.T) {
	fixture := platformApplicationsBundleFixture(t)
	bundle, _ := LoadPlatformApplicationsStageBundle(fixture.config)
	api := newPlatformApplicationsLauncherAPI(t)
	launcher := newPlatformApplicationsLauncher(t, bundle, api.client())
	mutator, err := NewPlatformApplicationsStageMutator(bundle.plan, bundle, launcher)
	if err != nil {
		t.Fatal(err)
	}
	result, err := mutator.Mutate(context.Background(), platformApplicationsMutationRequest(mutator))
	if err != nil || result.Outcome != "SUCCEEDED" || result.MutationState != "ATTEMPTED" || !stageReceiptPrefixDigestPattern.MatchString(result.EvidenceDigest) || result.TargetClusterUIDDigest != "" {
		t.Fatalf("unexpected platform-applications mutation result: %#v %v", result, err)
	}
}

func TestPlatformApplicationsStageMutatorMapsPartialAndUnknownOutcomesToStops(t *testing.T) {
	for name, test := range map[string]struct {
		configure    func(*platformApplicationsLauncherAPI)
		wantMutation string
	}{
		"known partial":       {configure: func(api *platformApplicationsLauncherAPI) { api.failPost = 2 }, wantMutation: "ATTEMPTED"},
		"unknown first write": {configure: func(api *platformApplicationsLauncherAPI) { api.errorPost = 1 }, wantMutation: "UNKNOWN"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := platformApplicationsBundleFixture(t)
			bundle, _ := LoadPlatformApplicationsStageBundle(fixture.config)
			api := newPlatformApplicationsLauncherAPI(t)
			test.configure(api)
			launcher := newPlatformApplicationsLauncher(t, bundle, api.client())
			mutator, _ := NewPlatformApplicationsStageMutator(bundle.plan, bundle, launcher)
			result, err := mutator.Mutate(context.Background(), platformApplicationsMutationRequest(mutator))
			if err == nil || result.Outcome != "STOPPED" || result.MutationState != test.wantMutation || !stageReceiptPrefixDigestPattern.MatchString(result.EvidenceDigest) {
				t.Fatalf("partial outcome was not bounded: %#v %v", result, err)
			}
		})
	}
}

func TestPlatformApplicationsStageMutatorRejectsMismatchedRequestAndBundle(t *testing.T) {
	fixture := platformApplicationsBundleFixture(t)
	bundle, _ := LoadPlatformApplicationsStageBundle(fixture.config)
	api := newPlatformApplicationsLauncherAPI(t)
	launcher := newPlatformApplicationsLauncher(t, bundle, api.client())
	mutator, _ := NewPlatformApplicationsStageMutator(bundle.plan, bundle, launcher)
	request := platformApplicationsMutationRequest(mutator)
	request.GrantID = ""
	if _, err := mutator.Mutate(context.Background(), request); err == nil || len(api.requests) != 0 {
		t.Fatal("mismatched request reached platform-applications API")
	}

	foreign := bundle
	foreign.receipt.PlanDigest = runnerStageSHA("f")
	if _, err := NewPlatformApplicationsStageMutator(bundle.plan, foreign, launcher); err == nil {
		t.Fatal("foreign bundle opened platform-applications mutator")
	}
	if _, err := NewPlatformApplicationsStageMutator(bundle.plan, bundle, nil); err == nil {
		t.Fatal("nil launcher opened platform-applications mutator")
	}
}

func platformApplicationsMutationRequest(mutator *PlatformApplicationsStageMutator) execution.StageMutationRequest {
	return execution.StageMutationRequest{
		StageMutationBinding: mutator.Binding(), ContractIdentity: mutator.identity,
		GrantID: "ok147-platform-applications-grant", PredecessorDigest: runnerStageSHA("7"),
	}
}
