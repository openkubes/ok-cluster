package runner

import (
	"errors"

	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

// StageResumeConfig contains only the immutable plan identity and an explicit
// canonical receipt prefix. It carries no grant, credential, endpoint or
// implementation selector.
type StageResumeConfig struct {
	PlanPath     string
	PlanExpected stageplan.Expected
	Receipts     []StageReceiptSource
}

// InspectStageResume verifies the complete receipt prefix and returns the only
// safe cursor decision. It performs no credential read, ledger access,
// Kubernetes request, mutation or stage execution.
func InspectStageResume(config StageResumeConfig) (stagecursor.Decision, error) {
	if config.Receipts == nil {
		return stagecursor.Decision{}, errors.New("stage receipt prefix must be explicit")
	}
	plan, err := stageplan.Load(config.PlanPath, config.PlanExpected)
	if err != nil {
		return stagecursor.Decision{}, err
	}
	prefix := make([]stagereceipt.Verified, 0, len(config.Receipts))
	predecessors := []stagereceipt.Verified{}
	for _, source := range config.Receipts {
		verified, err := stagereceipt.Load(source.Path, source.Digest, plan, predecessors)
		if err != nil {
			return stagecursor.Decision{}, err
		}
		prefix = append(prefix, verified)
		predecessors = []stagereceipt.Verified{verified}
	}
	cursor, err := stagecursor.Evaluate(plan, prefix)
	if err != nil {
		return stagecursor.Decision{}, err
	}
	return cursor.Decision()
}
