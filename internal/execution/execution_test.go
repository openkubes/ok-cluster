package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	requestpkg "github.com/openkubes/ok-cluster/internal/executor"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/submission"
)

var _ Observer = (*observation.AggregateObserver)(nil)

func TestRunCompletesOnlyAfterCurrentReadyObservation(t *testing.T) {
	fixture := executionFixture(t)
	store, err := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	operation := Operation{
		Ledger: store, Submitter: successfulSubmitter{mutationState: "ATTEMPTED"},
		Observer: observerFunc(readyObservation), Clock: advancingClock(fixture.at),
	}
	receipt, err := operation.Run(context.Background(), fixture.result, fixture.request, fixture.grant, fixture.root)
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" || receipt.Outcome == nil || receipt.Outcome.Outcome != "SUCCEEDED" {
		t.Fatalf("unexpected execution result: %#v %v", receipt, err)
	}
	inspection, err := store.Inspect(context.Background(), fixture.grant)
	if err != nil || inspection.State != "COMPLETED" || inspection.Outcome == nil || inspection.Outcome.EvidenceDigest != receipt.EvidenceDigest {
		t.Fatalf("durable outcome differs: %#v %v", inspection, err)
	}
}

func TestRunStaleObservationCompletesStopped(t *testing.T) {
	fixture := executionFixture(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	operation := Operation{
		Ledger: store, Submitter: successfulSubmitter{mutationState: "ATTEMPTED"},
		Observer: observerFunc(func(_ context.Context, policy observation.Policy) (observation.VerifiedResult, error) {
			bundle := readyBundle(policy)
			bundle.Evidence[0].ObservedGeneration = 1
			bundle.Evidence[0].Generation = 2
			return observation.Evaluate(policy, bundle)
		}), Clock: advancingClock(fixture.at),
	}
	receipt, err := operation.Run(context.Background(), fixture.result, fixture.request, fixture.grant, fixture.root)
	var resultErr *ResultError
	if !errors.As(err, &resultErr) || receipt.State != "COMPLETED_STOPPED" || receipt.Observation == nil || receipt.Observation.Ready != "Unknown" {
		t.Fatalf("stale evidence did not stop durably: %#v %v", receipt, err)
	}
}

func TestRunHistoricalReadyObservationCannotSucceed(t *testing.T) {
	fixture := executionFixture(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	operation := Operation{
		Ledger: store, Submitter: successfulSubmitter{mutationState: "ATTEMPTED"},
		Observer: observerFunc(func(_ context.Context, policy observation.Policy) (observation.VerifiedResult, error) {
			bundle := readyBundle(policy)
			bundle.EvaluatedAt = fixture.at.Add(-time.Second).Format(time.RFC3339Nano)
			return observation.Evaluate(policy, bundle)
		}), Clock: advancingClock(fixture.at),
	}
	receipt, err := operation.Run(context.Background(), fixture.result, fixture.request, fixture.grant, fixture.root)
	if err == nil || receipt.State != "COMPLETED_STOPPED" || receipt.Observation == nil || receipt.Observation.Ready != "True" {
		t.Fatalf("historical Ready was treated as current success: %#v %v", receipt, err)
	}
}

func TestRunObserverFailureLeavesClaimIndeterminate(t *testing.T) {
	fixture := executionFixture(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	operation := Operation{
		Ledger: store, Submitter: successfulSubmitter{mutationState: "ATTEMPTED"},
		Observer: observerFunc(func(context.Context, observation.Policy) (observation.VerifiedResult, error) {
			return observation.VerifiedResult{}, errors.New("observer unavailable")
		}), Clock: advancingClock(fixture.at),
	}
	receipt, err := operation.Run(context.Background(), fixture.result, fixture.request, fixture.grant, fixture.root)
	if err == nil || receipt.State != "CLAIMED_INDETERMINATE_STOP" || receipt.Outcome != nil {
		t.Fatalf("observer failure was not indeterminate: %#v %v", receipt, err)
	}
	inspection, inspectErr := store.Inspect(context.Background(), fixture.grant)
	if inspectErr != nil || inspection.State != "CLAIMED_INDETERMINATE_STOP" || inspection.ClaimAllowed {
		t.Fatalf("unsafe restart state: %#v %v", inspection, inspectErr)
	}
}

func TestRunRejectsObservationForDifferentRuntimePolicy(t *testing.T) {
	fixture := executionFixture(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	operation := Operation{
		Ledger: store, Submitter: successfulSubmitter{mutationState: "ATTEMPTED"},
		Observer: observerFunc(func(_ context.Context, policy observation.Policy) (observation.VerifiedResult, error) {
			policy.TargetClusterUID = "different-cluster-uid"
			return observation.Evaluate(policy, readyBundle(policy))
		}), Clock: advancingClock(fixture.at),
	}
	receipt, err := operation.Run(context.Background(), fixture.result, fixture.request, fixture.grant, fixture.root)
	if err == nil || receipt.State != "CLAIMED_INDETERMINATE_STOP" || receipt.Outcome != nil {
		t.Fatalf("foreign observation policy was accepted: %#v %v", receipt, err)
	}
}

func TestRunValidatesProjectionBeforeClaim(t *testing.T) {
	fixture := executionFixture(t)
	if err := os.WriteFile(filepath.Join(fixture.root, "ok-mgmt-lifecycle.yaml"), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	operation := Operation{Ledger: store, Submitter: staticSubmitter{}, Observer: observerFunc(readyObservation), Clock: advancingClock(fixture.at)}
	if _, err := operation.Run(context.Background(), fixture.result, fixture.request, fixture.grant, fixture.root); err == nil {
		t.Fatal("tampered projection accepted")
	}
	inspection, err := store.Inspect(context.Background(), fixture.grant)
	if err != nil || inspection.State != "AVAILABLE" || !inspection.ClaimAllowed {
		t.Fatalf("preclaim failure consumed grant: %#v %v", inspection, err)
	}
}

func TestRunSubmissionFailureIsDurablyStoppedWithoutObservation(t *testing.T) {
	fixture := executionFixture(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	observerCalls := 0
	operation := Operation{
		Ledger:    store,
		Submitter: staticSubmitter{receipt: submission.Receipt{Format: submission.RunReceiptFormat, IntentRevision: fixture.result.NormalizedDigest, State: "STOPPED_PARTIAL_OR_UNKNOWN", MutationState: "ATTEMPTED"}, err: errors.New("create denied")},
		Observer: observerFunc(func(context.Context, observation.Policy) (observation.VerifiedResult, error) {
			observerCalls++
			return observation.VerifiedResult{}, nil
		}), Clock: advancingClock(fixture.at),
	}
	receipt, err := operation.Run(context.Background(), fixture.result, fixture.request, fixture.grant, fixture.root)
	var resultErr *ResultError
	if !errors.As(err, &resultErr) || receipt.State != "COMPLETED_STOPPED" || receipt.Outcome == nil || receipt.Outcome.MutationState != "ATTEMPTED" || observerCalls != 0 {
		t.Fatalf("submission failure handling differs: %#v calls=%d err=%v", receipt, observerCalls, err)
	}
}

func TestRunDoesNotCallNoWriteIdempotencyLifecycleSuccess(t *testing.T) {
	fixture := executionFixture(t)
	store, _ := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	operation := Operation{
		Ledger: store, Submitter: successfulSubmitter{mutationState: "NOT_ATTEMPTED"},
		Observer: observerFunc(readyObservation), Clock: advancingClock(fixture.at),
	}
	receipt, err := operation.Run(context.Background(), fixture.result, fixture.request, fixture.grant, fixture.root)
	if err == nil || receipt.State != "COMPLETED_STOPPED" || receipt.Outcome == nil || receipt.Outcome.MutationState != "NOT_ATTEMPTED" {
		t.Fatalf("no-write operation claimed lifecycle success: %#v %v", receipt, err)
	}
}

type fixtureState struct {
	root    string
	at      time.Time
	result  contract.Result
	request requestpkg.CreateRequest
	grant   authorization.VerifiedGrant
}

func executionFixture(t *testing.T) fixtureState {
	t.Helper()
	raw, err := os.ReadFile("../contract/testdata/ok141-contract-v5.yaml")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("../contract/testdata/ok141-contract-v3.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	result, err := contract.Canonicalize(raw, schema)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := contract.ContractIdentity(result.Normalized)
	root := t.TempDir()
	infra := projectionYAML("v1", "Namespace", "", identity.Name, identity, result.NormalizedDigest)
	mgmt := projectionYAML("cluster.x-k8s.io/v1beta2", "Cluster", identity.Namespace, identity.Name, identity, result.NormalizedDigest)
	authority, _ := json.Marshal(map[string]any{
		"format": "ok141-contract-to-capi-projection/v2", "contractIdentity": identity, "intentRevision": result.NormalizedDigest,
		"infrastructurePlane": map[string]any{"identity": "ok-infra", "role": "provider-runtime-and-golden-image-prerequisites", "resources": []map[string]any{{"apiVersion": "v1", "kind": "Namespace", "name": identity.Name}}},
		"managementPlane":     map[string]any{"identity": "ok-mgmt", "role": "single-lifecycle-writer", "resources": []map[string]any{{"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster", "namespace": identity.Namespace, "name": identity.Name}}},
	})
	for name, value := range map[string][]byte{"authority-map.json": authority, "ok-infra-prerequisites.yaml": infra, "ok-mgmt-lifecycle.yaml": mgmt} {
		if err := os.WriteFile(filepath.Join(root, name), value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	binding := projection.Binding{
		Format: projection.BindingFormat, SourceFormat: "ok141-contract-to-capi-projection/v2",
		ManifestDigest: "sha256:" + strings.Repeat("b", 64), AuthorityMapDigest: digest.SHA256(authority),
		IntentRevision: result.NormalizedDigest, ContractIdentity: identity,
		InfrastructurePlane: projection.Plane{Identity: "ok-infra", Role: "provider-runtime-and-golden-image-prerequisites", ResourceCount: 1},
		ManagementPlane:     projection.Plane{Identity: "ok-mgmt", Role: "single-lifecycle-writer", ResourceCount: 1},
		Artifacts:           []projection.Artifact{{Name: "authority-map.json", Digest: digest.SHA256(authority)}, {Name: "ok-infra-prerequisites.yaml", Digest: digest.SHA256(infra)}, {Name: "ok-mgmt-lifecycle.yaml", Digest: digest.SHA256(mgmt)}},
	}
	request, err := requestpkg.NewCreateRequest(result, identity, binding)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	grant := signedGrant(t, request, at)
	return fixtureState{root: root, at: at, result: result, request: request, grant: grant}
}

func projectionYAML(apiVersion, kind, namespace, name string, identity contract.Identity, revision string) []byte {
	namespaceLine := ""
	if namespace != "" {
		namespaceLine = "  namespace: " + namespace + "\n"
	}
	return []byte("apiVersion: " + apiVersion + "\nkind: " + kind + "\nmetadata:\n  name: " + name + "\n" + namespaceLine + "  annotations:\n    openkubes.io/contract-name: " + identity.Name + "\n    openkubes.io/contract-namespace: " + identity.Namespace + "\n    openkubes.io/intent-revision: " + revision + "\n")
}

func signedGrant(t *testing.T, request requestpkg.CreateRequest, at time.Time) authorization.VerifiedGrant {
	t.Helper()
	requestDigest, _ := requestpkg.Digest(request)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	payload := authorization.Payload{
		Audience: authorization.Audience, GrantID: "ok147-execution-20260816-01", Decision: "ALLOW", Operation: request.Operation,
		RequestDigest: requestDigest, ContractIdentity: request.ContractIdentity, ContractRevision: request.ContractRevision,
		ProjectionManifestDigest: request.Projection.ManifestDigest, NotBefore: at.Add(-time.Minute).Format(time.RFC3339), NotAfter: at.Add(20 * time.Minute).Format(time.RFC3339), MaxUses: 1,
	}
	signed, _ := authorization.SigningBytes(payload)
	document, _ := json.Marshal(map[string]any{"format": authorization.Format, "payload": payload, "signature": map[string]any{"algorithm": "Ed25519", "keyId": digest.SHA256(publicKey), "value": base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed))}})
	grant, err := authorization.Verify(document, []byte(base64.StdEncoding.EncodeToString(publicKey)), request, at)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

type staticSubmitter struct {
	receipt submission.Receipt
	err     error
}

func (submitter staticSubmitter) Execute(context.Context, submission.Plan) (submission.Receipt, error) {
	return submitter.receipt, submitter.err
}

type successfulSubmitter struct{ mutationState string }

func (submitter successfulSubmitter) Execute(_ context.Context, plan submission.Plan) (submission.Receipt, error) {
	state := "CREATED"
	if submitter.mutationState == "NOT_ATTEMPTED" {
		state = "UNCHANGED"
	}
	planeReceipt := func(plane submission.Plane) *submission.PlaneReceipt {
		results := make([]submission.ObjectResult, 0, len(plane.Objects))
		for _, object := range plane.Objects {
			uid := "uid-" + object.Identity.Name
			if object.Identity.APIVersion == "cluster.x-k8s.io/v1beta2" && object.Identity.Kind == "Cluster" {
				uid = "capi-cluster-uid-1"
			}
			results = append(results, submission.ObjectResult{
				Identity: submission.ObjectIdentity{APIVersion: object.Identity.APIVersion, Kind: object.Identity.Kind, Name: object.Identity.Name, Namespace: object.Identity.Namespace},
				Digest:   object.Digest, UID: uid, State: state,
			})
		}
		return &submission.PlaneReceipt{Format: submission.PlaneReceiptFormat, Authority: plane.Identity, Role: plane.Role, State: "SUBMITTED", MutationState: submitter.mutationState, Results: results}
	}
	return submission.Receipt{
		Format: submission.RunReceiptFormat, IntentRevision: plan.IntentRevision,
		State: "SUBMITTED_OBSERVATION_PENDING", MutationState: submitter.mutationState,
		Infrastructure: planeReceipt(plan.Infrastructure), Management: planeReceipt(plan.Management),
	}, nil
}

type observerFunc func(context.Context, observation.Policy) (observation.VerifiedResult, error)

func (function observerFunc) Observe(ctx context.Context, policy observation.Policy) (observation.VerifiedResult, error) {
	return function(ctx, policy)
}

func readyObservation(_ context.Context, policy observation.Policy) (observation.VerifiedResult, error) {
	return observation.Evaluate(policy, readyBundle(policy))
}

func readyBundle(policy observation.Policy) observation.Bundle {
	evidenceDigest := "sha256:" + strings.Repeat("e", 64)
	return observation.Bundle{Format: observation.BundleFormat, IntentRevision: policy.IntentRevision, EvaluatedAt: "2026-08-16T10:00:01Z", Evidence: []observation.Evidence{
		{Type: "InfrastructureReady", Source: "CAPICluster", SourceUID: policy.TargetClusterUID, TargetClusterUID: policy.TargetClusterUID, Status: "True", Reason: "InfrastructureReady", DesiredRevision: policy.IntentRevision, ObservedRevision: policy.IntentRevision, Generation: 1, ObservedGeneration: 1, EvidenceDigest: evidenceDigest},
		{Type: "ControlPlaneAvailable", Source: "CAPICluster", SourceUID: policy.TargetClusterUID, TargetClusterUID: policy.TargetClusterUID, Status: "True", Reason: "ControlPlaneAvailable", DesiredRevision: policy.IntentRevision, ObservedRevision: policy.IntentRevision, Generation: 1, ObservedGeneration: 1, EvidenceDigest: evidenceDigest},
		{Type: "NetworkReady", Source: "BoundedNetworkEvaluator", SourceUID: "network-evidence-1", TargetClusterUID: policy.TargetClusterUID, Status: "True", Reason: "NetworkReady", DesiredRevision: policy.EnablementRevision, ObservedRevision: policy.EnablementRevision, EvidenceDigest: evidenceDigest},
		{Type: "PlatformReady", Source: "BoundedPlatformEvaluator", SourceUID: "platform-evidence-1", TargetClusterUID: policy.TargetClusterUID, Status: "True", Reason: "PlatformReady", DesiredRevision: policy.PlatformRevision, ObservedRevision: policy.PlatformRevision, EvidenceDigest: evidenceDigest},
	}}
}

func advancingClock(start time.Time) func() time.Time {
	current := start.Add(-time.Second)
	return func() time.Time {
		current = current.Add(time.Second)
		return current
	}
}
