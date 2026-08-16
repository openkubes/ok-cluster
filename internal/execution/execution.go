// Package execution composes verified authorization, immutable claim,
// exact-create submission and bounded observation. It contains no rendering,
// policy decision, retry, rollback or controller loop.
package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	requestpkg "github.com/openkubes/ok-cluster/internal/executor"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const ReceiptFormat = "ok147-bounded-execution-receipt/v1"

// Submitter is deliberately narrower than a Kubernetes client.
type Submitter interface {
	Execute(context.Context, submission.Plan) (submission.Receipt, error)
}

// Observer must return a result produced by the deterministic evaluator. An
// operational observer failure leaves the already claimed grant indeterminate.
type Observer interface {
	Observe(context.Context, observation.Policy) (observation.VerifiedResult, error)
}

// Operation requires explicit durable persistence, bounded capabilities and a
// clock. None has a permissive default.
type Operation struct {
	Ledger    *ledger.Ledger
	Submitter Submitter
	Observer  Observer
	Clock     func() time.Time
}

// Receipt is safe to retain as redacted execution evidence. Absence of Outcome
// after Claim means CLAIMED_INDETERMINATE_STOP.
type Receipt struct {
	Format         string                 `json:"format"`
	State          string                 `json:"state"`
	RequestDigest  string                 `json:"requestDigest"`
	Claim          *ledger.ClaimReceipt   `json:"claim,omitempty"`
	Submission     *submission.Receipt    `json:"submission,omitempty"`
	Observation    *observation.Receipt   `json:"observation,omitempty"`
	EvidenceDigest string                 `json:"evidenceDigest,omitempty"`
	Outcome        *ledger.OutcomeReceipt `json:"outcome,omitempty"`
}

// ResultError means the operation reached a durable non-success outcome. It is
// distinct from an indeterminate infrastructure/program error.
type ResultError struct {
	State string
}

func (err *ResultError) Error() string { return "bounded execution completed with " + err.State }

// Run performs all non-mutating validation before consuming the grant. Once a
// claim exists, every unexpected composition/observer/persistence error stops
// without retry and leaves restart inspection indeterminate.
func (operation Operation) Run(ctx context.Context, result contract.Result, request requestpkg.CreateRequest, grant authorization.VerifiedGrant, projectionRoot string) (Receipt, error) {
	receipt := Receipt{Format: ReceiptFormat, State: "PRECLAIM"}
	if operation.Ledger == nil || operation.Submitter == nil || operation.Observer == nil || operation.Clock == nil {
		return receipt, errors.New("execution ledger, submitter, observer, and clock are required")
	}
	requestDigest, policy, plan, err := preclaim(result, request, grant, projectionRoot)
	if err != nil {
		return receipt, err
	}
	receipt.RequestDigest = requestDigest
	claim, err := operation.Ledger.Claim(ctx, grant, operation.Clock())
	if err != nil {
		return receipt, err
	}
	receipt.Claim = &claim
	receipt.State = "CLAIMED_INDETERMINATE_STOP"

	submissionReceipt, submissionErr := operation.Submitter.Execute(ctx, plan)
	receipt.Submission = &submissionReceipt
	if submissionErr != nil {
		return operation.complete(ctx, receipt, "STOPPED", submissionReceipt.MutationState, operation.Clock())
	}
	clusterUID, err := submittedClusterUID(submissionReceipt, plan, request.ContractIdentity, request.ContractRevision)
	if err != nil {
		return receipt, fmt.Errorf("correlate submitted Cluster identity: %w", err)
	}
	policy, err = observation.BindTarget(policy, clusterUID)
	if err != nil {
		return receipt, err
	}
	verifiedObservation, err := operation.Observer.Observe(ctx, policy)
	if err != nil {
		return receipt, fmt.Errorf("bounded observation failed after claim: %w", err)
	}
	observationReceipt, err := verifiedObservation.Receipt()
	if err != nil {
		return receipt, err
	}
	receipt.Observation = &observationReceipt
	expectedPolicyDigest, err := observation.PolicyDigest(policy)
	if err != nil || observationReceipt.IntentRevision != request.ContractRevision || observationReceipt.PolicyDigest != expectedPolicyDigest {
		return receipt, errors.New("verified observation does not bind the execution policy")
	}
	claimTime, claimTimeErr := time.Parse(time.RFC3339Nano, claim.ClaimedAt)
	observationTime, observationTimeErr := time.Parse(time.RFC3339Nano, observationReceipt.EvaluatedAt)
	completedAt := operation.Clock()
	currentObservation := claimTimeErr == nil && observationTimeErr == nil && !observationTime.Before(claimTime) && !observationTime.After(completedAt)

	outcome := "STOPPED"
	if observationReceipt.Ready == "False" {
		outcome = "FAILED"
	} else if observationReceipt.Ready == "True" && currentObservation && submissionReceipt.MutationState == "ATTEMPTED" {
		outcome = "SUCCEEDED"
	}
	return operation.complete(ctx, receipt, outcome, submissionReceipt.MutationState, completedAt)
}

func preclaim(result contract.Result, request requestpkg.CreateRequest, grant authorization.VerifiedGrant, projectionRoot string) (string, observation.Policy, submission.Plan, error) {
	if request.Format != requestpkg.RequestFormat || request.Operation != "CreateCluster" || request.ContractRevision != result.NormalizedDigest || request.Projection.IntentRevision != result.NormalizedDigest || request.Projection.ContractIdentity != request.ContractIdentity {
		return "", observation.Policy{}, submission.Plan{}, errors.New("Contract result and CreateRequest do not describe one operation")
	}
	requestDigest, err := requestpkg.Digest(request)
	if err != nil {
		return "", observation.Policy{}, submission.Plan{}, err
	}
	binding, err := grant.ConsumptionBinding()
	if err != nil {
		return "", observation.Policy{}, submission.Plan{}, err
	}
	if binding.Operation != request.Operation || binding.RequestDigest != requestDigest || binding.ContractRevision != request.ContractRevision || binding.ProjectionManifestDigest != request.Projection.ManifestDigest {
		return "", observation.Policy{}, submission.Plan{}, errors.New("verified grant does not bind the CreateRequest")
	}
	policy, err := observation.PolicyFromContract(result)
	if err != nil {
		return "", observation.Policy{}, submission.Plan{}, err
	}
	plan, err := submission.Load(projectionRoot, request.Projection)
	if err != nil {
		return "", observation.Policy{}, submission.Plan{}, err
	}
	if plan.IntentRevision != request.ContractRevision || plan.AuthorityMapDigest != request.Projection.AuthorityMapDigest {
		return "", observation.Policy{}, submission.Plan{}, errors.New("submission plan differs from CreateRequest")
	}
	return requestDigest, policy, plan, nil
}

func submittedClusterUID(receipt submission.Receipt, plan submission.Plan, identity contract.Identity, revision string) (string, error) {
	if receipt.Format != submission.RunReceiptFormat || receipt.IntentRevision != revision || receipt.State != "SUBMITTED_OBSERVATION_PENDING" || receipt.Infrastructure == nil || receipt.Management == nil {
		return "", errors.New("submission did not reach observation boundary")
	}
	infraMutation, err := validatePlaneReceipt(*receipt.Infrastructure, plan.Infrastructure)
	if err != nil {
		return "", fmt.Errorf("infrastructure submission receipt: %w", err)
	}
	managementMutation, err := validatePlaneReceipt(*receipt.Management, plan.Management)
	if err != nil {
		return "", fmt.Errorf("management submission receipt: %w", err)
	}
	expectedMutation := "NOT_ATTEMPTED"
	if infraMutation == "ATTEMPTED" || managementMutation == "ATTEMPTED" {
		expectedMutation = "ATTEMPTED"
	}
	if receipt.MutationState != expectedMutation {
		return "", errors.New("submission mutation state is inconsistent")
	}
	var uid string
	for _, result := range receipt.Management.Results {
		if result.Identity.APIVersion == "cluster.x-k8s.io/v1beta2" && result.Identity.Kind == "Cluster" && result.Identity.Name == identity.Name && result.Identity.Namespace == identity.Namespace {
			if uid != "" || result.UID == "" {
				return "", errors.New("submission has ambiguous Cluster runtime identity")
			}
			uid = result.UID
		}
	}
	if uid == "" {
		return "", errors.New("submission has no exact Cluster runtime identity")
	}
	return uid, nil
}

func validatePlaneReceipt(receipt submission.PlaneReceipt, plan submission.Plane) (string, error) {
	if receipt.Format != submission.PlaneReceiptFormat || receipt.Authority != plan.Identity || receipt.Role != plan.Role || receipt.State != "SUBMITTED" || len(receipt.Results) != len(plan.Objects) {
		return "", errors.New("identity, state, or result count differs from submission plan")
	}
	expectedMutation := "NOT_ATTEMPTED"
	for index, result := range receipt.Results {
		expected := plan.Objects[index]
		if result.Identity.APIVersion != expected.Identity.APIVersion || result.Identity.Kind != expected.Identity.Kind || result.Identity.Name != expected.Identity.Name || result.Identity.Namespace != expected.Identity.Namespace || result.Digest != expected.Digest || result.UID == "" || len(result.UID) > 128 {
			return "", fmt.Errorf("object result %d differs from submission plan", index+1)
		}
		switch result.State {
		case "CREATED":
			expectedMutation = "ATTEMPTED"
		case "UNCHANGED":
		default:
			return "", fmt.Errorf("object result %d has invalid state", index+1)
		}
	}
	if receipt.MutationState != expectedMutation {
		return "", errors.New("plane mutation state is inconsistent")
	}
	return expectedMutation, nil
}

func (operation Operation) complete(ctx context.Context, receipt Receipt, outcome, mutationState string, completedAt time.Time) (Receipt, error) {
	receipt.State = "COMPLETION_PENDING"
	evidence := struct {
		Format        string               `json:"format"`
		RequestDigest string               `json:"requestDigest"`
		Claim         *ledger.ClaimReceipt `json:"claim"`
		Submission    *submission.Receipt  `json:"submission"`
		Observation   *observation.Receipt `json:"observation,omitempty"`
		Outcome       string               `json:"outcome"`
		MutationState string               `json:"mutationState"`
	}{
		Format: "ok147-bounded-execution-evidence/v1", RequestDigest: receipt.RequestDigest,
		Claim: receipt.Claim, Submission: receipt.Submission, Observation: receipt.Observation,
		Outcome: outcome, MutationState: mutationState,
	}
	evidenceDigest, err := canonicalDigest(evidence)
	if err != nil {
		receipt.State = "CLAIMED_INDETERMINATE_STOP"
		return receipt, err
	}
	receipt.EvidenceDigest = evidenceDigest
	completed, err := operation.Ledger.Complete(ctx, *receipt.Claim, outcome, mutationState, evidenceDigest, completedAt)
	if err != nil {
		receipt.State = "CLAIMED_INDETERMINATE_STOP"
		return receipt, fmt.Errorf("persist bounded execution outcome: %w", err)
	}
	receipt.Outcome = &completed
	receipt.State = "COMPLETED_" + outcome
	if outcome != "SUCCEEDED" {
		return receipt, &ResultError{State: receipt.State}
	}
	return receipt, nil
}

func canonicalDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return "", err
	}
	canonical, err := contract.JCS(generic)
	if err != nil {
		return "", err
	}
	return digest.SHA256(canonical), nil
}
