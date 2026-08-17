package runner

import (
	"context"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/execution"
)

func TestTargetRegistrationStageMutatorReturnsBoundedSuccess(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	material, _ := BuildTargetRegistrationMaterial(fixture.config)
	api := newTargetRegistrationLauncherAPI(t)
	launcher := newTargetRegistrationLauncher(t, material, api.client(), fixture.config.MaterializationTime.Add(time.Minute))
	mutator, err := NewTargetRegistrationStageMutator(fixture.bundle.plan, material, launcher)
	if err != nil {
		t.Fatal(err)
	}
	request := targetRegistrationMutationRequest(mutator)
	result, err := mutator.Mutate(context.Background(), request)
	if err != nil || result.Outcome != "SUCCEEDED" || result.MutationState != "ATTEMPTED" || !stageReceiptPrefixDigestPattern.MatchString(result.EvidenceDigest) || result.TargetClusterUIDDigest != "" {
		t.Fatalf("unexpected target-registration mutation result: %#v %v", result, err)
	}
}

func TestTargetRegistrationStageMutatorMapsPartialAndUnknownOutcomesToStops(t *testing.T) {
	for name, test := range map[string]struct {
		configure    func(*targetRegistrationLauncherAPI)
		wantMutation string
	}{
		"known partial":       {configure: func(api *targetRegistrationLauncherAPI) { api.failPost = 2 }, wantMutation: "ATTEMPTED"},
		"unknown first write": {configure: func(api *targetRegistrationLauncherAPI) { api.errorPost = 1 }, wantMutation: "UNKNOWN"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := targetRegistrationMaterialFixture(t)
			material, _ := BuildTargetRegistrationMaterial(fixture.config)
			api := newTargetRegistrationLauncherAPI(t)
			test.configure(api)
			launcher := newTargetRegistrationLauncher(t, material, api.client(), fixture.config.MaterializationTime.Add(time.Minute))
			mutator, _ := NewTargetRegistrationStageMutator(fixture.bundle.plan, material, launcher)
			result, err := mutator.Mutate(context.Background(), targetRegistrationMutationRequest(mutator))
			if err == nil || result.Outcome != "STOPPED" || result.MutationState != test.wantMutation || !stageReceiptPrefixDigestPattern.MatchString(result.EvidenceDigest) {
				t.Fatalf("partial outcome was not bounded: %#v %v", result, err)
			}
		})
	}
}

func TestTargetRegistrationStageMutatorRejectsMismatchedRequestAndMaterial(t *testing.T) {
	fixture := targetRegistrationMaterialFixture(t)
	material, _ := BuildTargetRegistrationMaterial(fixture.config)
	api := newTargetRegistrationLauncherAPI(t)
	launcher := newTargetRegistrationLauncher(t, material, api.client(), fixture.config.MaterializationTime.Add(time.Minute))
	mutator, _ := NewTargetRegistrationStageMutator(fixture.bundle.plan, material, launcher)
	request := targetRegistrationMutationRequest(mutator)
	request.GrantID = ""
	if _, err := mutator.Mutate(context.Background(), request); err == nil || len(api.requests) != 0 {
		t.Fatal("mismatched request reached target-registration API")
	}

	foreign := material
	foreign.receipt.PlanDigest = runnerStageSHA("f")
	if _, err := NewTargetRegistrationStageMutator(fixture.bundle.plan, foreign, launcher); err == nil {
		t.Fatal("foreign material opened target-registration mutator")
	}
	if _, err := NewTargetRegistrationStageMutator(fixture.bundle.plan, material, nil); err == nil {
		t.Fatal("nil launcher opened target-registration mutator")
	}
}

func targetRegistrationMutationRequest(mutator *TargetRegistrationStageMutator) execution.StageMutationRequest {
	return execution.StageMutationRequest{
		StageMutationBinding: mutator.Binding(), ContractIdentity: mutator.identity,
		GrantID: "ok147-target-registration-grant", PredecessorDigest: runnerStageSHA("7"),
	}
}
