package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestSubmissionPlaneMutatorCompletesStagedOperation(t *testing.T) {
	plan := stagedPlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	projected := stagedSubmissionPlan(plan.IntentRevision, plan.Authorities.Infrastructure, plan.Authorities.Management)
	submitter := &fakePlaneSubmitter{receipt: successfulPlaneReceipt(projected.Infrastructure, "CREATED", "ATTEMPTED")}
	mutator, err := NewSubmissionPlaneMutator(plan, "provider-prerequisites", projected, submitter)
	if err != nil {
		t.Fatal(err)
	}
	cursor, _ := stagecursor.Evaluate(plan, []stagereceipt.Verified{})
	grant := stagedGrant(t, plan, "provider-prerequisites", []stagereceipt.Verified{}, at)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	receipt, err := (StagedOperation{Ledger: store, Mutator: mutator, Clock: stagedClock(at)}).Run(context.Background(), plan, cursor, grant)
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageReceiptDigest == "" || submitter.calls != 1 {
		t.Fatalf("typed submission stage did not complete: %#v calls=%d err=%v", receipt, submitter.calls, err)
	}
}

func TestLifecycleSubmissionPersistsRuntimeCorrelationAcrossResume(t *testing.T) {
	plan := stagedPlan(t)
	at := time.Date(2026, 8, 16, 18, 0, 0, 0, time.UTC)
	provider, err := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", stagedSHA("1"), stagedSHA("e"), at)
	if err != nil {
		t.Fatal(err)
	}
	projected := stagedSubmissionPlan(plan.IntentRevision, plan.Authorities.Infrastructure, plan.Authorities.Management)
	submissionReceipt := successfulPlaneReceipt(projected.Management, "CREATED", "ATTEMPTED")
	const targetUID = "cluster-runtime-uid-147"
	submissionReceipt.Results[0].UID = targetUID
	mutator, err := NewSubmissionPlaneMutator(plan, "cluster-lifecycle", projected, &fakePlaneSubmitter{receipt: submissionReceipt})
	if err != nil {
		t.Fatal(err)
	}
	cursor, _ := stagecursor.Evaluate(plan, []stagereceipt.Verified{provider})
	grant := stagedGrant(t, plan, "cluster-lifecycle", []stagereceipt.Verified{provider}, at.Add(time.Second))
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	receipt, err := (StagedOperation{Ledger: store, Mutator: mutator, Clock: stagedClock(at.Add(time.Second))}).Run(context.Background(), plan, cursor, grant)
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" {
		t.Fatalf("lifecycle stage did not complete: %#v %v", receipt, err)
	}
	verified, err := store.LoadStageReceipt(context.Background(), plan, "cluster-lifecycle", receipt.StageReceiptDigest, []stagereceipt.Verified{provider})
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := verified.Receipt()
	if stored.TargetClusterUIDDigest != digest.SHA256([]byte(targetUID)) {
		t.Fatalf("runtime correlation did not survive durable resume: %#v", stored)
	}
	resumed, err := stagecursor.Evaluate(plan, []stagereceipt.Verified{provider, verified})
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := resumed.Decision()
	if decision.StageID != "lifecycle-observation" || decision.State != "NEXT" {
		t.Fatalf("runtime-bound lifecycle receipt did not resume observation: %#v", decision)
	}
}

func TestSubmissionPlaneMutatorBindsOneAuthorityPlane(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedSubmissionPlan(plan.IntentRevision, plan.Authorities.Infrastructure, plan.Authorities.Management)
	submitter := &fakePlaneSubmitter{receipt: successfulPlaneReceipt(projected.Infrastructure, "CREATED", "ATTEMPTED")}
	mutator, err := NewSubmissionPlaneMutator(plan, "provider-prerequisites", projected, submitter)
	if err != nil {
		t.Fatal(err)
	}
	projected.Infrastructure.Objects[0].Raw[0] = 'x'
	result, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding()))
	if err != nil || result.Outcome != "SUCCEEDED" || result.MutationState != "ATTEMPTED" || result.EvidenceDigest == "" || submitter.calls != 1 {
		t.Fatalf("unexpected plane mutation: %#v calls=%d err=%v", result, submitter.calls, err)
	}
	if string(submitter.plane.Objects[0].Raw) != "{\"apiVersion\":\"v1\",\"kind\":\"Namespace\"}" || submitter.plane.Identity != plan.Authorities.Infrastructure {
		t.Fatalf("mutator did not retain the verified authority plane: %#v", submitter.plane)
	}
}

func TestSubmissionPlaneMutatorNoWriteCannotClaimStageSuccess(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedSubmissionPlan(plan.IntentRevision, plan.Authorities.Infrastructure, plan.Authorities.Management)
	submitter := &fakePlaneSubmitter{receipt: successfulPlaneReceipt(projected.Management, "UNCHANGED", "NOT_ATTEMPTED")}
	mutator, err := NewSubmissionPlaneMutator(plan, "cluster-lifecycle", projected, submitter)
	if err != nil {
		t.Fatal(err)
	}
	result, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding()))
	if err != nil || result.Outcome != "STOPPED" || result.MutationState != "NOT_ATTEMPTED" {
		t.Fatalf("no-write submission claimed success: %#v %v", result, err)
	}
}

func TestSubmissionPlaneMutatorBindsLifecycleRuntimeIdentityWithoutExposingUID(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedSubmissionPlan(plan.IntentRevision, plan.Authorities.Infrastructure, plan.Authorities.Management)
	receipt := successfulPlaneReceipt(projected.Management, "CREATED", "ATTEMPTED")
	const runtimeUID = "cluster-runtime-uid-147"
	receipt.Results[0].UID = runtimeUID
	mutator, err := NewSubmissionPlaneMutator(plan, "cluster-lifecycle", projected, &fakePlaneSubmitter{receipt: receipt})
	if err != nil {
		t.Fatal(err)
	}
	result, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding()))
	if err != nil {
		t.Fatal(err)
	}
	if result.TargetClusterUIDDigest != digest.SHA256([]byte(runtimeUID)) || bytes.Contains([]byte(result.TargetClusterUIDDigest), []byte(runtimeUID)) {
		t.Fatalf("runtime identity was not safely bound: %#v", result)
	}
}

func TestSubmissionPlaneMutatorRejectsMissingLifecycleRuntimeIdentity(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedSubmissionPlan(plan.IntentRevision, plan.Authorities.Infrastructure, plan.Authorities.Management)
	receipt := successfulPlaneReceipt(projected.Management, "CREATED", "ATTEMPTED")
	receipt.Results[0].UID = ""
	mutator, _ := NewSubmissionPlaneMutator(plan, "cluster-lifecycle", projected, &fakePlaneSubmitter{receipt: receipt})
	if _, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding())); err == nil {
		t.Fatal("successful lifecycle submission without runtime identity was accepted")
	}
}

func TestSubmissionPlaneMutatorPreservesPartialStoppedEvidence(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedSubmissionPlan(plan.IntentRevision, plan.Authorities.Infrastructure, plan.Authorities.Management)
	receipt := successfulPlaneReceipt(projected.Infrastructure, "CREATED", "ATTEMPTED")
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	submitter := &fakePlaneSubmitter{receipt: receipt, err: errors.New("sensitive API detail")}
	mutator, _ := NewSubmissionPlaneMutator(plan, "provider-prerequisites", projected, submitter)
	result, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding()))
	if err == nil || err.Error() != "bounded submission stopped" || result.Outcome != "STOPPED" || result.MutationState != "ATTEMPTED" || result.EvidenceDigest == "" {
		t.Fatalf("partial submission result was not redacted and retained: %#v %v", result, err)
	}
}

func TestSubmissionPlaneMutatorPreservesFailedFirstCreateAttempt(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedSubmissionPlan(plan.IntentRevision, plan.Authorities.Infrastructure, plan.Authorities.Management)
	receipt := submission.PlaneReceipt{
		Format: submission.PlaneReceiptFormat, Authority: projected.Management.Identity,
		Role: projected.Management.Role, State: "STOPPED_PARTIAL_OR_UNKNOWN",
		MutationState: "ATTEMPTED", Results: []submission.ObjectResult{},
	}
	submitter := &fakePlaneSubmitter{receipt: receipt, err: errors.New("sensitive API detail")}
	mutator, _ := NewSubmissionPlaneMutator(plan, "cluster-lifecycle", projected, submitter)
	result, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding()))
	if err == nil || err.Error() != "bounded submission stopped" || result.Outcome != "STOPPED" || result.MutationState != "ATTEMPTED" || result.EvidenceDigest == "" {
		t.Fatalf("failed first create attempt was not durably classifiable: %#v %v", result, err)
	}
}

func TestSubmissionPlaneMutatorRejectsWrongStageAuthorityAndRequest(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedSubmissionPlan(plan.IntentRevision, plan.Authorities.Infrastructure, plan.Authorities.Management)
	submitter := &fakePlaneSubmitter{}
	if _, err := NewSubmissionPlaneMutator(plan, "enablement", projected, submitter); err == nil {
		t.Fatal("generic submission adapter accepted Enablement stage")
	}
	wrong := projected
	wrong.Infrastructure.Identity = plan.Authorities.Management
	if _, err := NewSubmissionPlaneMutator(plan, "provider-prerequisites", wrong, submitter); err == nil {
		t.Fatal("submission adapter accepted a different authority plane")
	}
	mutator, _ := NewSubmissionPlaneMutator(plan, "provider-prerequisites", projected, submitter)
	request := stagedMutationRequest(t, plan, mutator.Binding())
	request.ContractIdentity.Name = "another-cluster"
	if _, err := mutator.Mutate(context.Background(), request); err == nil || submitter.calls != 0 {
		t.Fatalf("foreign mutation request reached submitter: calls=%d err=%v", submitter.calls, err)
	}
}

func TestSubmissionPlaneMutatorRejectsMalformedReceipt(t *testing.T) {
	plan := stagedPlan(t)
	projected := stagedSubmissionPlan(plan.IntentRevision, plan.Authorities.Infrastructure, plan.Authorities.Management)
	receipt := successfulPlaneReceipt(projected.Infrastructure, "CREATED", "ATTEMPTED")
	receipt.Results[0].Digest = stagedSHA("0")
	submitter := &fakePlaneSubmitter{receipt: receipt}
	mutator, _ := NewSubmissionPlaneMutator(plan, "provider-prerequisites", projected, submitter)
	if _, err := mutator.Mutate(context.Background(), stagedMutationRequest(t, plan, mutator.Binding())); err == nil {
		t.Fatal("malformed submission receipt was accepted")
	}
}

type fakePlaneSubmitter struct {
	receipt submission.PlaneReceipt
	err     error
	calls   int
	plane   submission.Plane
}

func (submitter *fakePlaneSubmitter) Submit(_ context.Context, plane submission.Plane) (submission.PlaneReceipt, error) {
	submitter.calls++
	submitter.plane = plane
	return submitter.receipt, submitter.err
}

func stagedSubmissionPlan(revision, infrastructure, management string) submission.Plan {
	object := func(apiVersion, kind, namespace, name, value string) submission.Object {
		return submission.Object{
			Identity: projection.ResourceIdentity{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name},
			Digest:   stagedSHA(value), CollectionPath: "/apis/example/v1/resources", ObjectPath: "/apis/example/v1/resources/" + name,
			Raw: json.RawMessage("{\"apiVersion\":\"v1\",\"kind\":\"Namespace\"}"),
		}
	}
	return submission.Plan{
		Format: submission.PlanFormat, IntentRevision: revision, AuthorityMapDigest: stagedSHA("9"),
		Infrastructure: submission.Plane{Identity: infrastructure, Role: "provider-runtime-and-golden-image-prerequisites", Objects: []submission.Object{object("v1", "Namespace", "", "disposable-ok147", "7")}},
		Management:     submission.Plane{Identity: management, Role: "single-lifecycle-writer", Objects: []submission.Object{object("cluster.x-k8s.io/v1beta2", "Cluster", "disposable-ok147", "disposable-ok147", "8")}},
	}
}

func successfulPlaneReceipt(plane submission.Plane, state, mutationState string) submission.PlaneReceipt {
	results := make([]submission.ObjectResult, len(plane.Objects))
	for index, object := range plane.Objects {
		results[index] = submission.ObjectResult{
			Identity: submission.ObjectIdentity{APIVersion: object.Identity.APIVersion, Kind: object.Identity.Kind, Namespace: object.Identity.Namespace, Name: object.Identity.Name},
			Digest:   object.Digest, UID: "runtime-object-uid", State: state,
		}
	}
	return submission.PlaneReceipt{
		Format: submission.PlaneReceiptFormat, Authority: plane.Identity, Role: plane.Role,
		State: "SUBMITTED", MutationState: mutationState, Results: results,
	}
}

func stagedMutationRequest(t *testing.T, plan stageplan.Binding, binding StageMutationBinding) StageMutationRequest {
	t.Helper()
	return StageMutationRequest{
		StageMutationBinding: binding,
		ContractIdentity:     plan.ContractIdentity,
		GrantID:              "ok147-stage-grant-20260816-01",
		PredecessorDigest:    stagedSHA("6"),
	}
}
