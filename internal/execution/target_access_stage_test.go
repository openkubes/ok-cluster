package execution

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestTargetAccessMutatorBindsExactWorkloadAccessSet(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedTargetAccessPlan(plan.IntentRevision, plan.PlatformRevision, plan.ExecutionFixture, stagedSHA("e"))
	submitter := &targetAccessSubmitterSpy{receipt: successfulPlaneReceipt(projected.Workload, "CREATED", "ATTEMPTED")}
	mutator, err := NewTargetAccessMutator(plan, projected, submitter)
	if err != nil {
		t.Fatal(err)
	}
	projected.Workload.Objects[0].Raw[0] = 'x'
	request := stagedMutationRequest(t, plan, mutator.Binding())
	result, err := mutator.Mutate(context.Background(), request)
	if err != nil || result.Outcome != "SUCCEEDED" || result.MutationState != "ATTEMPTED" || result.EvidenceDigest == "" || submitter.calls != 1 {
		t.Fatalf("target-access mutation did not complete: %#v calls=%d err=%v", result, submitter.calls, err)
	}
	if !reflect.DeepEqual(submitter.dispatch.Mutation, request) {
		t.Fatalf("stage authorization binding was not forwarded unchanged: got %#v want %#v", submitter.dispatch.Mutation, request)
	}
	if submitter.dispatch.DispatchID == "" || submitter.dispatch.DispatchID[:7] != "sha256:" || submitter.dispatch.ArtifactDigest != projected.ArtifactDigest || submitter.dispatch.TargetIdentityDigest != projected.TargetIdentityDigest {
		t.Fatalf("dispatch identity or artifact binding was not forwarded: %#v", submitter.dispatch)
	}
	if submitter.dispatch.Plane.Identity != stagedSHA("e") || len(submitter.dispatch.Plane.Objects) != submission.TargetAccessObjectCount || submitter.dispatch.Plane.Objects[0].Identity.Kind != "Namespace" || string(submitter.dispatch.Plane.Objects[0].Raw) != `{"apiVersion":"v1","kind":"Namespace"}` {
		t.Fatalf("mutator did not retain the verified workload plane: %#v", submitter.dispatch.Plane)
	}
}

func TestTargetAccessMutatorPreservesStoppedEvidence(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedTargetAccessPlan(plan.IntentRevision, plan.PlatformRevision, plan.ExecutionFixture, stagedSHA("e"))
	receipt := successfulPlaneReceipt(projected.Workload, "CREATED", "ATTEMPTED")
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	mutator, err := NewTargetAccessMutator(plan, projected, DirectTargetAccessSubmitter{Submitter: &fakePlaneSubmitter{receipt: receipt, err: errors.New("sensitive API detail")}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding()))
	if err == nil || err.Error() != "bounded target-access submission stopped" || result.Outcome != "STOPPED" || result.MutationState != "ATTEMPTED" || result.EvidenceDigest == "" {
		t.Fatalf("target-access stop was not redacted and retained: %#v %v", result, err)
	}
}

func TestTargetAccessMutatorFailsClosedOnInvalidSuccessReceipt(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedTargetAccessPlan(plan.IntentRevision, plan.PlatformRevision, plan.ExecutionFixture, stagedSHA("e"))
	tests := map[string]func(*submission.PlaneReceipt){
		"missing object result": func(receipt *submission.PlaneReceipt) {
			receipt.Results = receipt.Results[:len(receipt.Results)-1]
		},
		"wrong authority": func(receipt *submission.PlaneReceipt) {
			receipt.Authority = stagedSHA("1")
		},
		"inconsistent mutation state": func(receipt *submission.PlaneReceipt) {
			receipt.MutationState = "NOT_ATTEMPTED"
		},
		"wrong object digest": func(receipt *submission.PlaneReceipt) {
			receipt.Results[0].Digest = stagedSHA("2")
		},
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			receipt := successfulPlaneReceipt(projected.Workload, "CREATED", "ATTEMPTED")
			corrupt(&receipt)
			submitter := &targetAccessSubmitterSpy{receipt: receipt}
			mutator, err := NewTargetAccessMutator(plan, projected, submitter)
			if err != nil {
				t.Fatal(err)
			}
			result, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding()))
			if err == nil || result.Outcome == "SUCCEEDED" || result.MutationState == "ATTEMPTED" || submitter.calls != 1 {
				t.Fatalf("invalid submission evidence was accepted: %#v calls=%d err=%v", result, submitter.calls, err)
			}
		})
	}
}

func TestTargetAccessMutatorRejectsForeignProjectionAndRequest(t *testing.T) {
	plan := stagedPlan(t)
	valid := stagedTargetAccessPlan(plan.IntentRevision, plan.PlatformRevision, plan.ExecutionFixture, stagedSHA("e"))
	tests := map[string]func(*submission.TargetAccessPlan){
		"authorizing input":     func(value *submission.TargetAccessPlan) { value.MutationAllowed = true },
		"wrong P":               func(value *submission.TargetAccessPlan) { value.PlatformRevision = stagedSHA("1") },
		"wrong artifact":        func(value *submission.TargetAccessPlan) { value.ArtifactDigest = stagedSHA("1") },
		"wrong authority":       func(value *submission.TargetAccessPlan) { value.Workload.Identity = stagedSHA("1") },
		"incomplete object set": func(value *submission.TargetAccessPlan) { value.Workload.Objects = value.Workload.Objects[:10] },
		"wrong kind":            func(value *submission.TargetAccessPlan) { value.Workload.Objects[0].Identity.Kind = "ConfigMap" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneTargetAccessPlan(valid)
			mutate(&candidate)
			if _, err := NewTargetAccessMutator(plan, candidate, DirectTargetAccessSubmitter{Submitter: &fakePlaneSubmitter{}}); err == nil {
				t.Fatal("foreign target-access projection was accepted")
			}
		})
	}
	mutator, _ := NewTargetAccessMutator(plan, valid, DirectTargetAccessSubmitter{Submitter: &fakePlaneSubmitter{}})
	request := stagedMutationRequest(t, plan, mutator.Binding())
	request.ContractIdentity.Name = "other"
	if _, err := mutator.Mutate(context.Background(), request); err == nil {
		t.Fatal("foreign target-access request was accepted")
	}
	spy := &targetAccessSubmitterSpy{}
	mutator, _ = NewTargetAccessMutator(plan, valid, spy)
	request = stagedMutationRequest(t, plan, mutator.Binding())
	request.ExecutionAttemptDigest = stagedSHA("2")
	if _, err := mutator.Mutate(context.Background(), request); err == nil || spy.calls != 0 {
		t.Fatal("foreign execution attempt reached the target-access submitter")
	}
	request = stagedMutationRequest(t, plan, mutator.Binding())
	request.AuthorizationEnvelope[0] ^= 1
	if _, err := mutator.Mutate(context.Background(), request); err == nil || spy.calls != 0 {
		t.Fatal("tampered signed authorization reached the target-access submitter")
	}
	request = stagedMutationRequest(t, plan, mutator.Binding())
	request.verifiedStageGrant = false
	if _, err := mutator.Mutate(context.Background(), request); err == nil || spy.calls != 0 {
		t.Fatal("request without the StagedOperation verification marker reached the target-access submitter")
	}
}

type targetAccessSubmitterSpy struct {
	receipt  submission.PlaneReceipt
	err      error
	calls    int
	dispatch TargetAccessDispatch
}

func (submitter *targetAccessSubmitterSpy) SubmitTargetAccess(_ context.Context, dispatch TargetAccessDispatch) (submission.PlaneReceipt, error) {
	submitter.calls++
	submitter.dispatch = dispatch
	return submitter.receipt, submitter.err
}

func TestTargetAccessDispatchIDIsStableAndGrantBound(t *testing.T) {
	plan := stagedPlan(t)
	mutator, err := NewTargetAccessMutator(plan, stagedTargetAccessPlan(plan.IntentRevision, plan.PlatformRevision, plan.ExecutionFixture, stagedSHA("e")), &targetAccessSubmitterSpy{})
	if err != nil {
		t.Fatal(err)
	}
	request := stagedMutationRequest(t, plan, mutator.Binding())
	first, err := targetAccessDispatchID(request, stagedSHA("0"), stagedSHA("e"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := targetAccessDispatchID(request, stagedSHA("0"), stagedSHA("e"))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("dispatch identity is not deterministic: %s != %s", first, second)
	}
	variants := []struct {
		name, artifact, target, attempt string
		request                         StageMutationRequest
	}{
		{name: "grant", artifact: stagedSHA("0"), target: stagedSHA("e"), attempt: request.ExecutionAttemptDigest, request: request},
		{name: "artifact", artifact: stagedSHA("1"), target: stagedSHA("e"), attempt: request.ExecutionAttemptDigest, request: stagedMutationRequest(t, plan, mutator.Binding())},
		{name: "target", artifact: stagedSHA("0"), target: stagedSHA("f"), attempt: request.ExecutionAttemptDigest, request: stagedMutationRequest(t, plan, mutator.Binding())},
		{name: "attempt", artifact: stagedSHA("0"), target: stagedSHA("e"), attempt: stagedSHA("2"), request: stagedMutationRequest(t, plan, mutator.Binding())},
		{name: "authorization", artifact: stagedSHA("0"), target: stagedSHA("e"), attempt: request.ExecutionAttemptDigest, request: stagedMutationRequest(t, plan, mutator.Binding())},
	}
	variants[0].request.GrantID += "-different"
	variants[4].request.AuthorizationDigest = stagedSHA("4")
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			variant.request.ExecutionAttemptDigest = variant.attempt
			got, err := targetAccessDispatchID(variant.request, variant.artifact, variant.target)
			if err != nil {
				t.Fatal(err)
			}
			if first == got {
				t.Fatalf("dispatch identity did not bind changed %s", variant.name)
			}
		})
	}
}

func TestTargetAccessDispatchJSONIsNotACompleteWireRequest(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedTargetAccessPlan(plan.IntentRevision, plan.PlatformRevision, plan.ExecutionFixture, stagedSHA("e"))
	spy := &targetAccessSubmitterSpy{receipt: successfulPlaneReceipt(projected.Workload, "CREATED", "ATTEMPTED")}
	mutator, err := NewTargetAccessMutator(plan, projected, spy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding())); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(spy.dispatch)
	if err != nil {
		t.Fatal(err)
	}
	var decoded TargetAccessDispatch
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for index, object := range decoded.Plane.Objects {
		if len(object.Raw) != 0 {
			t.Fatalf("ordinary JSON unexpectedly became a reviewed wire protocol at object %d", index)
		}
	}
	if len(decoded.Plane.Objects) != submission.TargetAccessObjectCount || decoded.DispatchID != spy.dispatch.DispatchID {
		t.Fatal("test did not demonstrate the incomplete serialization boundary")
	}
}

func stagedTargetAccessPlan(r, p, fixture, targetDigest string) submission.TargetAccessPlan {
	kinds := []string{"Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Role", "RoleBinding", "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRole", "ClusterRole", "ClusterRole", "ClusterRole"}
	digestCharacters := "123456789abcdef0"
	objects := make([]submission.Object, len(kinds))
	for index, kind := range kinds {
		objects[index] = submission.Object{
			Identity: projection.ResourceIdentity{APIVersion: "v1", Kind: kind, Name: "object"},
			Digest:   stagedSHA(string(digestCharacters[index])), CollectionPath: "/api/v1/resources", ObjectPath: "/api/v1/resources/object",
			Raw: json.RawMessage(`{"apiVersion":"v1","kind":"` + kind + `"}`),
		}
	}
	return submission.TargetAccessPlan{
		Format: submission.TargetAccessPlanFormat, IntentRevision: r, PlatformRevision: p, ExecutionFixture: fixture,
		TargetIdentityDigest: targetDigest, ArtifactDigest: stagedSHA("0"), MutationAllowed: false,
		Workload: submission.Plane{Identity: targetDigest, Role: "target-access-writer", Objects: objects},
	}
}

func cloneTargetAccessPlan(source submission.TargetAccessPlan) submission.TargetAccessPlan {
	clone := source
	clone.Workload.Objects = make([]submission.Object, len(source.Workload.Objects))
	for index, object := range source.Workload.Objects {
		clone.Workload.Objects[index] = object
		clone.Workload.Objects[index].Raw = append([]byte(nil), object.Raw...)
	}
	return clone
}
