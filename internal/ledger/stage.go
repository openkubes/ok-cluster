package ledger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	StageClaimFormat   = "ok147-stage-grant-claim/v1"
	StageOutcomeFormat = "ok147-stage-operation-receipt/v1"
)

type StageClaimReceipt struct {
	Format              string `json:"format"`
	State               string `json:"state"`
	AuthorizationDigest string `json:"authorizationDigest"`
	GrantID             string `json:"grantId"`
	KeyID               string `json:"keyId"`
	PlanDigest          string `json:"planDigest"`
	StageID             string `json:"stageId"`
	StageDigest         string `json:"stageDigest"`
	Operation           string `json:"operation"`
	Authority           string `json:"authority"`
	PredecessorDigest   string `json:"predecessorDigest"`
	ContractRevision    string `json:"contractRevision"`
	ClaimedAt           string `json:"claimedAt"`
}

type StageOutcomeReceipt struct {
	Format                 string `json:"format"`
	State                  string `json:"state"`
	GrantID                string `json:"grantId"`
	PlanDigest             string `json:"planDigest"`
	StageID                string `json:"stageId"`
	StageDigest            string `json:"stageDigest"`
	Operation              string `json:"operation"`
	ClaimDigest            string `json:"claimDigest"`
	Outcome                string `json:"outcome"`
	MutationState          string `json:"mutationState"`
	EvidenceDigest         string `json:"evidenceDigest"`
	TargetClusterUIDDigest string `json:"targetClusterUidDigest,omitempty"`
	CompletedAt            string `json:"completedAt"`
}

type StageInspection struct {
	State         string               `json:"state"`
	ClaimAllowed  bool                 `json:"claimAllowed"`
	ClaimDigest   string               `json:"claimDigest,omitempty"`
	OutcomeDigest string               `json:"outcomeDigest,omitempty"`
	Outcome       *StageOutcomeReceipt `json:"outcome,omitempty"`
}

// ClaimStage atomically consumes one verified stage grant in the same global
// grant-ID namespace as CreateCluster grants.
func (ledger *Ledger) ClaimStage(ctx context.Context, grant authorization.VerifiedStageGrant, at time.Time) (StageClaimReceipt, error) {
	binding, err := grant.ConsumptionBinding()
	if err != nil {
		return StageClaimReceipt{}, err
	}
	starts, err := time.Parse(time.RFC3339, binding.NotBefore)
	if err != nil {
		return StageClaimReceipt{}, fmt.Errorf("stage grant start: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, binding.NotAfter)
	if err != nil {
		return StageClaimReceipt{}, fmt.Errorf("stage grant expiration: %w", err)
	}
	if at.Before(starts) || !at.Before(expires) {
		return StageClaimReceipt{}, errors.New("stage grant is not active at consumption time")
	}
	receipt := StageClaimReceipt{
		Format: StageClaimFormat, State: "CLAIMED", AuthorizationDigest: binding.AuthorizationDigest,
		GrantID: binding.GrantID, KeyID: binding.KeyID, PlanDigest: binding.PlanDigest,
		StageID: binding.StageID, StageDigest: binding.StageDigest, Operation: binding.Operation,
		Authority: binding.Authority, PredecessorDigest: binding.PredecessorDigest, ContractRevision: binding.ContractRevision,
		ClaimedAt: at.UTC().Format(time.RFC3339Nano),
	}
	raw, _, err := canonicalRecord(receipt)
	if err != nil {
		return StageClaimReceipt{}, err
	}
	if err := ledger.store.Create(ctx, "claims", recordKey(binding.GrantID), raw); err != nil {
		if errors.Is(err, ErrRecordExists) {
			return StageClaimReceipt{}, ErrGrantConsumed
		}
		return StageClaimReceipt{}, fmt.Errorf("write stage grant claim: %w", err)
	}
	return receipt, nil
}

// CompleteStage records one immutable result. An exact repeat is idempotent;
// a successful mutating stage must have attempted its mutation.
func (ledger *Ledger) CompleteStage(ctx context.Context, claim StageClaimReceipt, outcome, mutationState, evidenceDigest string, at time.Time) (StageOutcomeReceipt, error) {
	return ledger.CompleteStageWithTarget(ctx, claim, outcome, mutationState, evidenceDigest, "", at)
}

// CompleteStageWithTarget records the irreversible runtime correlation from a
// successful Cluster lifecycle create without retaining the raw Kubernetes
// UID in redaction-safe ledger evidence.
func (ledger *Ledger) CompleteStageWithTarget(ctx context.Context, claim StageClaimReceipt, outcome, mutationState, evidenceDigest, targetClusterUIDDigest string, at time.Time) (StageOutcomeReceipt, error) {
	if !allowed(outcome, "SUCCEEDED", "FAILED", "STOPPED") || !allowed(mutationState, "NOT_ATTEMPTED", "ATTEMPTED", "UNKNOWN") {
		return StageOutcomeReceipt{}, errors.New("stage completion state is invalid")
	}
	if outcome == "SUCCEEDED" && mutationState != "ATTEMPTED" && !(claim.StageID == "provider-prerequisites" && mutationState == "NOT_ATTEMPTED") {
		return StageOutcomeReceipt{}, errors.New("successful mutating stage requires mutationState ATTEMPTED")
	}
	if !validDigest(evidenceDigest) {
		return StageOutcomeReceipt{}, errors.New("stage evidence digest is invalid")
	}
	if targetClusterUIDDigest != "" && (claim.StageID != "cluster-lifecycle" || outcome != "SUCCEEDED" || !validDigest(targetClusterUIDDigest)) {
		return StageOutcomeReceipt{}, errors.New("stage target Cluster identity binding is invalid")
	}
	stored, claimDigest, err := ledger.readStageClaim(ctx, claim.GrantID)
	if err != nil {
		return StageOutcomeReceipt{}, err
	}
	_, providedDigest, err := canonicalRecord(claim)
	if err != nil || claimDigest != providedDigest || stored != claim {
		return StageOutcomeReceipt{}, errors.New("provided stage claim differs from immutable ledger claim")
	}
	claimedAt, err := time.Parse(time.RFC3339Nano, claim.ClaimedAt)
	if err != nil || at.Before(claimedAt) {
		return StageOutcomeReceipt{}, errors.New("stage completion time precedes claim")
	}
	receipt := StageOutcomeReceipt{
		Format: StageOutcomeFormat, State: "COMPLETED", GrantID: claim.GrantID,
		PlanDigest: claim.PlanDigest, StageID: claim.StageID, StageDigest: claim.StageDigest,
		Operation: claim.Operation, ClaimDigest: claimDigest, Outcome: outcome,
		MutationState: mutationState, EvidenceDigest: evidenceDigest, TargetClusterUIDDigest: targetClusterUIDDigest,
		CompletedAt: at.UTC().Format(time.RFC3339Nano),
	}
	raw, expectedDigest, err := canonicalRecord(receipt)
	if err != nil {
		return StageOutcomeReceipt{}, err
	}
	if err := ledger.store.Create(ctx, "outcomes", recordKey(claim.GrantID), raw); err != nil {
		if !errors.Is(err, ErrRecordExists) {
			return StageOutcomeReceipt{}, fmt.Errorf("write stage outcome: %w", err)
		}
		existing, existingDigest, readErr := ledger.readStageOutcome(ctx, claim.GrantID)
		if readErr != nil {
			return StageOutcomeReceipt{}, readErr
		}
		if existingDigest == expectedDigest && existing == receipt {
			return existing, nil
		}
		return StageOutcomeReceipt{}, errors.New("conflicting stage outcome already exists")
	}
	return receipt, nil
}

func (ledger *Ledger) InspectStage(ctx context.Context, grant authorization.VerifiedStageGrant) (StageInspection, error) {
	binding, err := grant.ConsumptionBinding()
	if err != nil {
		return StageInspection{}, err
	}
	claim, claimDigest, err := ledger.readStageClaim(ctx, binding.GrantID)
	if errors.Is(err, ErrRecordNotFound) {
		return StageInspection{State: "AVAILABLE", ClaimAllowed: true}, nil
	}
	if err != nil {
		return StageInspection{}, err
	}
	if err := matchStageBinding(claim, binding); err != nil {
		return StageInspection{}, err
	}
	outcome, outcomeDigest, err := ledger.readStageOutcome(ctx, binding.GrantID)
	if errors.Is(err, ErrRecordNotFound) {
		return StageInspection{State: "CLAIMED_INDETERMINATE_STOP", ClaimAllowed: false, ClaimDigest: claimDigest}, nil
	}
	if err != nil {
		return StageInspection{}, err
	}
	if outcome.ClaimDigest != claimDigest || outcome.GrantID != claim.GrantID || outcome.PlanDigest != claim.PlanDigest || outcome.StageDigest != claim.StageDigest || outcome.Operation != claim.Operation {
		return StageInspection{}, errors.New("stage outcome does not match immutable claim")
	}
	return StageInspection{State: "COMPLETED", ClaimAllowed: false, ClaimDigest: claimDigest, OutcomeDigest: outcomeDigest, Outcome: &outcome}, nil
}

func (ledger *Ledger) readStageClaim(ctx context.Context, grantID string) (StageClaimReceipt, string, error) {
	var value StageClaimReceipt
	raw, err := ledger.store.Get(ctx, "claims", recordKey(grantID))
	if err != nil {
		return value, "", err
	}
	if err := jsonstrict.Decode(raw, &value); err != nil {
		return value, "", fmt.Errorf("decode stage grant claim: %w", err)
	}
	canonical, identity, err := canonicalRecord(value)
	if err != nil {
		return value, "", err
	}
	if !bytes.Equal(raw, canonical) {
		return value, "", errors.New("stage grant claim is not canonical or was modified")
	}
	return value, identity, validateStageClaim(value)
}

func (ledger *Ledger) readStageOutcome(ctx context.Context, grantID string) (StageOutcomeReceipt, string, error) {
	var value StageOutcomeReceipt
	raw, err := ledger.store.Get(ctx, "outcomes", recordKey(grantID))
	if err != nil {
		return value, "", err
	}
	if err := jsonstrict.Decode(raw, &value); err != nil {
		return value, "", fmt.Errorf("decode stage outcome: %w", err)
	}
	canonical, identity, err := canonicalRecord(value)
	if err != nil {
		return value, "", err
	}
	if !bytes.Equal(raw, canonical) {
		return value, "", errors.New("stage outcome is not canonical or was modified")
	}
	return value, identity, validateStageOutcome(value)
}

func validateStageClaim(value StageClaimReceipt) error {
	if value.Format != StageClaimFormat || value.State != "CLAIMED" || value.GrantID == "" || value.StageID == "" || value.Operation == "" || value.Authority == "" {
		return errors.New("stage grant claim is incomplete")
	}
	for _, identity := range []string{value.AuthorizationDigest, value.KeyID, value.PlanDigest, value.StageDigest, value.PredecessorDigest, value.ContractRevision} {
		if !validDigest(identity) {
			return errors.New("stage grant claim contains an invalid digest")
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, value.ClaimedAt); err != nil {
		return errors.New("stage grant claim has an invalid timestamp")
	}
	return nil
}

func validateStageOutcome(value StageOutcomeReceipt) error {
	if value.Format != StageOutcomeFormat || value.State != "COMPLETED" || value.GrantID == "" || value.StageID == "" || value.Operation == "" {
		return errors.New("stage outcome is incomplete")
	}
	if !allowed(value.Outcome, "SUCCEEDED", "FAILED", "STOPPED") || !allowed(value.MutationState, "NOT_ATTEMPTED", "ATTEMPTED", "UNKNOWN") {
		return errors.New("stage outcome contains an invalid state")
	}
	for _, identity := range []string{value.PlanDigest, value.StageDigest, value.ClaimDigest, value.EvidenceDigest} {
		if !validDigest(identity) {
			return errors.New("stage outcome contains an invalid digest")
		}
	}
	if value.TargetClusterUIDDigest != "" && (value.StageID != "cluster-lifecycle" || value.Outcome != "SUCCEEDED" || !validDigest(value.TargetClusterUIDDigest)) {
		return errors.New("stage outcome contains an invalid target Cluster identity binding")
	}
	if _, err := time.Parse(time.RFC3339Nano, value.CompletedAt); err != nil {
		return errors.New("stage outcome has an invalid timestamp")
	}
	if value.Outcome == "SUCCEEDED" && value.MutationState != "ATTEMPTED" && !(value.StageID == "provider-prerequisites" && value.MutationState == "NOT_ATTEMPTED") {
		return errors.New("successful stage outcome lacks attempted mutation state")
	}
	return nil
}

func matchStageBinding(claim StageClaimReceipt, binding authorization.StageConsumptionBinding) error {
	if claim.AuthorizationDigest != binding.AuthorizationDigest || claim.GrantID != binding.GrantID || claim.KeyID != binding.KeyID || claim.PlanDigest != binding.PlanDigest || claim.StageID != binding.StageID || claim.StageDigest != binding.StageDigest || claim.Operation != binding.Operation || claim.Authority != binding.Authority || claim.PredecessorDigest != binding.PredecessorDigest || claim.ContractRevision != binding.ContractRevision {
		return errors.New("stored stage claim differs from verified authorization")
	}
	return nil
}
