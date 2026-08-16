// Package stagecursor verifies a durable receipt prefix and selects exactly
// one next stage. It does not execute, authorize or persist stage work.
package stagecursor

import (
	"errors"
	"fmt"

	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

const DecisionFormat = "ok147-stage-cursor-decision/v1"

type Predecessor struct {
	StageID       string `json:"stageId"`
	ReceiptDigest string `json:"receiptDigest"`
}

// Decision is a redaction-safe description of NEXT, COMPLETED or STOPPED.
type Decision struct {
	Format                string        `json:"format"`
	State                 string        `json:"state"`
	PlanDigest            string        `json:"planDigest"`
	CompletedStages       int           `json:"completedStages"`
	StageID               string        `json:"stageId,omitempty"`
	StageOrder            int           `json:"stageOrder,omitempty"`
	StageDigest           string        `json:"stageDigest,omitempty"`
	Kind                  string        `json:"kind,omitempty"`
	Authority             string        `json:"authority,omitempty"`
	Operation             string        `json:"operation,omitempty"`
	RequiresAuthorization bool          `json:"requiresAuthorization"`
	Predecessors          []Predecessor `json:"predecessors"`
	TerminalOutcome       string        `json:"terminalOutcome,omitempty"`
	TerminalReceiptDigest string        `json:"terminalReceiptDigest,omitempty"`
}

// Cursor can only be produced by evaluating verified canonical receipts.
type Cursor struct {
	decision     Decision
	predecessors []stagereceipt.Verified
	verified     bool
}

func (cursor Cursor) Decision() (Decision, error) {
	if !cursor.verified {
		return Decision{}, errors.New("stage cursor was not produced by verification")
	}
	decision := cursor.decision
	decision.Predecessors = append([]Predecessor{}, cursor.decision.Predecessors...)
	return decision, nil
}

func (cursor Cursor) Predecessors() ([]stagereceipt.Verified, error) {
	if !cursor.verified {
		return nil, errors.New("stage cursor was not produced by verification")
	}
	return append([]stagereceipt.Verified{}, cursor.predecessors...), nil
}

// Evaluate verifies an explicit, gap-free receipt prefix and returns the only
// safe next decision. Any terminal receipt closes the sequence permanently.
func Evaluate(plan stageplan.Binding, prefix []stagereceipt.Verified) (Cursor, error) {
	if prefix == nil {
		return Cursor{}, errors.New("stage receipt prefix must be explicit")
	}
	if len(prefix) > len(plan.Stages) {
		return Cursor{}, errors.New("stage receipt prefix exceeds the staged plan")
	}
	previous := []stagereceipt.Verified{}
	for index, verified := range prefix {
		expected := plan.Stages[index]
		raw, err := verified.Bytes()
		if err != nil {
			return Cursor{}, err
		}
		receiptDigest, err := verified.Digest()
		if err != nil {
			return Cursor{}, err
		}
		rechecked, err := stagereceipt.Verify(raw, receiptDigest, plan, previous)
		if err != nil {
			return Cursor{}, fmt.Errorf("verify stage receipt prefix item %d: %w", index+1, err)
		}
		receipt, err := rechecked.Receipt()
		if err != nil {
			return Cursor{}, err
		}
		if receipt.StageID != expected.ID || receipt.StageOrder != expected.Order {
			return Cursor{}, errors.New("stage receipt prefix is reordered or contains a gap")
		}
		if receipt.State != "SUCCEEDED" {
			if index != len(prefix)-1 {
				return Cursor{}, errors.New("stage receipt prefix continues after a terminal outcome")
			}
			return verifiedCursor(Decision{
				Format: DecisionFormat, State: "STOPPED", PlanDigest: plan.PlanDigest,
				CompletedStages: index, StageID: receipt.StageID, StageOrder: receipt.StageOrder,
				StageDigest: receipt.StageDigest, Kind: receipt.Kind, Authority: receipt.Authority,
				Operation: receipt.Operation, RequiresAuthorization: false,
				Predecessors: explicitPredecessors(receipt.Predecessors), TerminalOutcome: receipt.State,
				TerminalReceiptDigest: receiptDigest,
			}, nil), nil
		}
		previous = []stagereceipt.Verified{rechecked}
	}
	if len(prefix) == len(plan.Stages) {
		return verifiedCursor(Decision{
			Format: DecisionFormat, State: "COMPLETED", PlanDigest: plan.PlanDigest,
			CompletedStages: len(prefix), RequiresAuthorization: false, Predecessors: []Predecessor{},
		}, nil), nil
	}
	next, nextDigest, err := plan.Stage(plan.Stages[len(prefix)].ID)
	if err != nil {
		return Cursor{}, err
	}
	predecessors := make([]Predecessor, len(previous))
	for index, verified := range previous {
		receipt, err := verified.Receipt()
		if err != nil {
			return Cursor{}, err
		}
		receiptDigest, err := verified.Digest()
		if err != nil {
			return Cursor{}, err
		}
		predecessors[index] = Predecessor{StageID: receipt.StageID, ReceiptDigest: receiptDigest}
	}
	return verifiedCursor(Decision{
		Format: DecisionFormat, State: "NEXT", PlanDigest: plan.PlanDigest,
		CompletedStages: len(prefix), StageID: next.ID, StageOrder: next.Order,
		StageDigest: nextDigest, Kind: next.Kind, Authority: next.Authority,
		Operation: next.GrantOperation, RequiresAuthorization: stageplan.IsMutating(next),
		Predecessors: predecessors,
	}, previous), nil
}

func verifiedCursor(decision Decision, predecessors []stagereceipt.Verified) Cursor {
	return Cursor{decision: decision, predecessors: append([]stagereceipt.Verified{}, predecessors...), verified: true}
}

func explicitPredecessors(source []stagereceipt.Predecessor) []Predecessor {
	result := make([]Predecessor, len(source))
	for index, predecessor := range source {
		result[index] = Predecessor{StageID: predecessor.StageID, ReceiptDigest: predecessor.ReceiptDigest}
	}
	return result
}
