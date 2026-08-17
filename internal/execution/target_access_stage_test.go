package execution

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestTargetAccessMutatorBindsExactWorkloadAccessSet(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedTargetAccessPlan(plan.IntentRevision, plan.PlatformRevision, plan.ExecutionFixture, stagedSHA("e"))
	submitter := &fakePlaneSubmitter{receipt: successfulPlaneReceipt(projected.Workload, "CREATED", "ATTEMPTED")}
	mutator, err := NewTargetAccessMutator(plan, projected, submitter)
	if err != nil {
		t.Fatal(err)
	}
	projected.Workload.Objects[0].Raw[0] = 'x'
	result, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding()))
	if err != nil || result.Outcome != "SUCCEEDED" || result.MutationState != "ATTEMPTED" || result.EvidenceDigest == "" || submitter.calls != 1 {
		t.Fatalf("target-access mutation did not complete: %#v calls=%d err=%v", result, submitter.calls, err)
	}
	if submitter.plane.Identity != stagedSHA("e") || len(submitter.plane.Objects) != 8 || submitter.plane.Objects[0].Identity.Kind != "Namespace" || string(submitter.plane.Objects[0].Raw) != `{"apiVersion":"v1","kind":"Namespace"}` {
		t.Fatalf("mutator did not retain the verified workload plane: %#v", submitter.plane)
	}
}

func TestTargetAccessMutatorPreservesStoppedEvidence(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedTargetAccessPlan(plan.IntentRevision, plan.PlatformRevision, plan.ExecutionFixture, stagedSHA("e"))
	receipt := successfulPlaneReceipt(projected.Workload, "CREATED", "ATTEMPTED")
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	mutator, err := NewTargetAccessMutator(plan, projected, &fakePlaneSubmitter{receipt: receipt, err: errors.New("sensitive API detail")})
	if err != nil {
		t.Fatal(err)
	}
	result, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding()))
	if err == nil || err.Error() != "bounded target-access submission stopped" || result.Outcome != "STOPPED" || result.MutationState != "ATTEMPTED" || result.EvidenceDigest == "" {
		t.Fatalf("target-access stop was not redacted and retained: %#v %v", result, err)
	}
}

func TestTargetAccessMutatorRejectsForeignProjectionAndRequest(t *testing.T) {
	plan := stagedPlan(t)
	valid := stagedTargetAccessPlan(plan.IntentRevision, plan.PlatformRevision, plan.ExecutionFixture, stagedSHA("e"))
	tests := map[string]func(*submission.TargetAccessPlan){
		"authorizing input": func(value *submission.TargetAccessPlan) { value.MutationAllowed = true },
		"wrong P":           func(value *submission.TargetAccessPlan) { value.PlatformRevision = stagedSHA("1") },
		"wrong artifact":    func(value *submission.TargetAccessPlan) { value.ArtifactDigest = stagedSHA("1") },
		"wrong authority":   func(value *submission.TargetAccessPlan) { value.Workload.Identity = stagedSHA("1") },
		"seventh object":    func(value *submission.TargetAccessPlan) { value.Workload.Objects = value.Workload.Objects[:7] },
		"wrong kind":        func(value *submission.TargetAccessPlan) { value.Workload.Objects[0].Identity.Kind = "ConfigMap" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneTargetAccessPlan(valid)
			mutate(&candidate)
			if _, err := NewTargetAccessMutator(plan, candidate, &fakePlaneSubmitter{}); err == nil {
				t.Fatal("foreign target-access projection was accepted")
			}
		})
	}
	mutator, _ := NewTargetAccessMutator(plan, valid, &fakePlaneSubmitter{})
	request := stagedMutationRequest(t, plan, mutator.Binding())
	request.ContractIdentity.Name = "other"
	if _, err := mutator.Mutate(context.Background(), request); err == nil {
		t.Fatal("foreign target-access request was accepted")
	}
}

func stagedTargetAccessPlan(r, p, fixture, targetDigest string) submission.TargetAccessPlan {
	kinds := []string{"Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Role", "RoleBinding"}
	objects := make([]submission.Object, len(kinds))
	for index, kind := range kinds {
		objects[index] = submission.Object{
			Identity: projection.ResourceIdentity{APIVersion: "v1", Kind: kind, Name: "object"},
			Digest:   stagedSHA(string("12345678"[index])), CollectionPath: "/api/v1/resources", ObjectPath: "/api/v1/resources/object",
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
