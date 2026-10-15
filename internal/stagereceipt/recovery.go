package stagereceipt

import (
	"encoding/json"
	"errors"

	"github.com/openkubes/ok-cluster/internal/stageplan"
)

// InheritFourStagePrefix retains the exact source bytes and identities. It
// attaches a verification context, not newly fabricated successful outcomes.
// The higher-level recovery verifier must independently validate the one
// corrected profile and pin the non-authorizing recovery binding digest.
func InheritFourStagePrefix(source, successor stageplan.Binding, prefix []Verified, bindingDigest string) ([]Verified, error) {
	if !receiptDigestPattern.MatchString(bindingDigest) || source.RecoverySourcePlanDigest != "" || source.ExecutionAttempt != "" ||
		successor.RecoverySourcePlanDigest != source.PlanDigest || successor.PlanDigest == source.PlanDigest || len(prefix) != 4 ||
		len(source.Stages) != 7 || len(successor.Stages) != 7 || source.CompletionMode != stageplan.CompletionModeBareClusterMVP ||
		source.ContractIdentity != successor.ContractIdentity || source.IntentRevision != successor.IntentRevision ||
		source.EnablementRevision != successor.EnablementRevision || source.PlatformRevision != successor.PlatformRevision ||
		source.ExecutionFixture != successor.ExecutionFixture || source.Authorities != successor.Authorities ||
		source.NetworkObservationMode != successor.NetworkObservationMode || source.CompletionMode != successor.CompletionMode {
		return nil, errors.New("recovery source, successor or four-stage prefix differs")
	}
	for i, candidate := range source.Stages {
		old, _, oldErr := source.Stage(candidate.ID)
		next, _, nextErr := successor.Stage(candidate.ID)
		if oldErr != nil || nextErr != nil {
			return nil, errors.New("recovery plan is not verified")
		}
		if i == 4 {
			if len(old.Inputs) != 1 || len(next.Inputs) != 1 || old.Inputs[0].Name != "stage.network-observation" || next.Inputs[0].Name != old.Inputs[0].Name || next.Inputs[0].Digest == old.Inputs[0].Digest {
				return nil, errors.New("recovery must change exactly the Stage-5 profile input")
			}
			next.Inputs[0].Digest = old.Inputs[0].Digest
		}
		a, _ := json.Marshal(old)
		b, _ := json.Marshal(next)
		if string(a) != string(b) {
			return nil, errors.New("recovery changes an unapproved stage field")
		}
	}
	result := make([]Verified, 4)
	previous := []Verified{}
	for i, original := range prefix {
		raw, err := original.Bytes()
		if err != nil {
			return nil, err
		}
		d, err := original.Digest()
		if err != nil {
			return nil, err
		}
		checked, err := Verify(raw, d, source, previous)
		if err != nil || checked.receipt.State != "SUCCEEDED" || checked.receipt.StageOrder != i+1 {
			return nil, errors.New("recovery requires four exact successful source receipts")
		}
		previous = []Verified{checked}
		checked.recoveryPlan, checked.recoveryDigest = successor.PlanDigest, bindingDigest
		copySource := source
		checked.sourcePlan = &copySource
		result[i] = checked
	}
	if !receiptDigestPattern.MatchString(result[1].receipt.TargetClusterUIDDigest) {
		return nil, errors.New("source prefix lacks durable target identity")
	}
	return result, nil
}

// Reverify retains the source-plan identity for inherited receipts and checks
// every new successor receipt with its explicit recovery context. Ordinary
// Verify continues rejecting foreign-plan receipts and recovery without context.
func (v Verified) Reverify(plan stageplan.Binding, previous []Verified) (Verified, error) {
	if v.sourcePlan == nil {
		return Verify(v.raw, v.digest, plan, previous)
	}
	if !v.verified || v.recoveryPlan != plan.PlanDigest || plan.RecoverySourcePlanDigest != v.sourcePlan.PlanDigest || v.receipt.StageOrder > 4 {
		return Verified{}, errors.New("inherited receipt recovery context differs")
	}
	plain := append([]Verified{}, previous...)
	for i := range plain {
		if plain[i].recoveryPlan != v.recoveryPlan || plain[i].recoveryDigest != v.recoveryDigest {
			return Verified{}, errors.New("mixed recovery binding predecessors")
		}
		plain[i].recoveryPlan, plain[i].recoveryDigest, plain[i].sourcePlan = "", "", nil
	}
	checked, err := Verify(v.raw, v.digest, *v.sourcePlan, plain)
	if err != nil {
		return Verified{}, err
	}
	checked.recoveryPlan, checked.recoveryDigest, checked.sourcePlan = v.recoveryPlan, v.recoveryDigest, v.sourcePlan
	return checked, nil
}

func (v Verified) InheritedFor(plan stageplan.Binding) bool {
	return v.verified && v.sourcePlan != nil && v.recoveryPlan == plan.PlanDigest && v.sourcePlan.PlanDigest == plan.RecoverySourcePlanDigest
}
