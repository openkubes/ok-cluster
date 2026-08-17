package execution

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestEnablementMutatorBindsOneHCPAndManagementWriter(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedEnablementPlan(plan.Authorities.Management, plan.IntentRevision, plan.EnablementRevision, plan.ExecutionFixture)
	submitter := &fakePlaneSubmitter{receipt: successfulPlaneReceipt(projected.Management, "CREATED", "ATTEMPTED")}
	mutator, err := NewEnablementMutator(plan, projected, submitter)
	if err != nil {
		t.Fatal(err)
	}
	projected.Management.Objects[0].Raw[0] = 'x'
	result, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding()))
	if err != nil || result.Outcome != "SUCCEEDED" || result.MutationState != "ATTEMPTED" || result.EvidenceDigest == "" || submitter.calls != 1 {
		t.Fatalf("enablement mutation did not complete: %#v calls=%d err=%v", result, submitter.calls, err)
	}
	if submitter.plane.Identity != plan.Authorities.Management || submitter.plane.Objects[0].Identity.Kind != "HelmChartProxy" || string(submitter.plane.Objects[0].Raw) != `{"apiVersion":"addons.cluster.x-k8s.io/v1alpha1","kind":"HelmChartProxy"}` {
		t.Fatalf("mutator did not retain the verified HCP plane: %#v", submitter.plane)
	}
}

func TestEnablementMutatorPreservesStoppedEvidence(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedEnablementPlan(plan.Authorities.Management, plan.IntentRevision, plan.EnablementRevision, plan.ExecutionFixture)
	receipt := successfulPlaneReceipt(projected.Management, "CREATED", "ATTEMPTED")
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	mutator, err := NewEnablementMutator(plan, projected, &fakePlaneSubmitter{receipt: receipt, err: errors.New("sensitive API detail")})
	if err != nil {
		t.Fatal(err)
	}
	result, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding()))
	if err == nil || err.Error() != "bounded enablement submission stopped" || result.Outcome != "STOPPED" || result.MutationState != "ATTEMPTED" || result.EvidenceDigest == "" {
		t.Fatalf("enablement stop was not redacted and retained: %#v %v", result, err)
	}
}

func TestEnablementMutatorRejectsForeignProjectionAndRequest(t *testing.T) {
	plan := stagedPlan(t)
	valid := stagedEnablementPlan(plan.Authorities.Management, plan.IntentRevision, plan.EnablementRevision, plan.ExecutionFixture)
	tests := map[string]func(*submission.EnablementPlan){
		"authorizing input": func(value *submission.EnablementPlan) { value.MutationAllowed = true },
		"wrong E":           func(value *submission.EnablementPlan) { value.EnablementRevision = stagedSHA("0") },
		"wrong artifact":    func(value *submission.EnablementPlan) { value.ArtifactDigest = stagedSHA("0") },
		"wrong authority":   func(value *submission.EnablementPlan) { value.Management.Identity = plan.Authorities.Infrastructure },
		"second object": func(value *submission.EnablementPlan) {
			value.Management.Objects = append(value.Management.Objects, value.Management.Objects[0])
		},
		"wrong kind": func(value *submission.EnablementPlan) { value.Management.Objects[0].Identity.Kind = "HelmReleaseProxy" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneEnablementPlan(valid)
			mutate(&candidate)
			if _, err := NewEnablementMutator(plan, candidate, &fakePlaneSubmitter{}); err == nil {
				t.Fatal("foreign enablement projection was accepted")
			}
		})
	}
	mutator, _ := NewEnablementMutator(plan, valid, &fakePlaneSubmitter{})
	request := stagedMutationRequest(t, plan, mutator.Binding())
	request.ContractIdentity.Name = "other"
	if _, err := mutator.Mutate(context.Background(), request); err == nil {
		t.Fatal("foreign enablement request was accepted")
	}
}

func stagedEnablementPlan(authority, r, e, fixture string) submission.EnablementPlan {
	object := submission.Object{
		Identity: projection.ResourceIdentity{APIVersion: "addons.cluster.x-k8s.io/v1alpha1", Kind: "HelmChartProxy", Namespace: "disposable-ok147", Name: "disposable-ok147-cilium"},
		Digest:   stagedSHA("5"), CollectionPath: "/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/disposable-ok147/helmchartproxies",
		ObjectPath: "/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/disposable-ok147/helmchartproxies/disposable-ok147-cilium",
		Raw:        json.RawMessage(`{"apiVersion":"addons.cluster.x-k8s.io/v1alpha1","kind":"HelmChartProxy"}`),
	}
	return submission.EnablementPlan{
		Format: submission.EnablementPlanFormat, IntentRevision: r, EnablementRevision: e, ExecutionFixture: fixture,
		ArtifactDigest: stagedSHA("d"), MutationAllowed: false,
		Management: submission.Plane{Identity: authority, Role: "enablement-desired-state-writer", Objects: []submission.Object{object}},
	}
}

func cloneEnablementPlan(source submission.EnablementPlan) submission.EnablementPlan {
	clone := source
	clone.Management.Objects = make([]submission.Object, len(source.Management.Objects))
	for index, object := range source.Management.Objects {
		clone.Management.Objects[index] = object
		clone.Management.Objects[index].Raw = append([]byte(nil), object.Raw...)
	}
	return clone
}
