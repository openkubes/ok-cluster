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
	_, cursor, err := loadStageResume(config)
	if err != nil {
		return stagecursor.Decision{}, err
	}
	return cursor.Decision()
}

func loadStageResume(config StageResumeConfig) (stageplan.Binding, stagecursor.Cursor, error) {
	plan, cursor, _, err := loadStageResumeWithPrefix(config)
	return plan, cursor, err
}

func loadStageResumeWithPrefix(config StageResumeConfig) (stageplan.Binding, stagecursor.Cursor, []stagereceipt.Verified, error) {
	if config.Receipts == nil {
		return stageplan.Binding{}, stagecursor.Cursor{}, nil, errors.New("stage receipt prefix must be explicit")
	}
	plan, err := stageplan.Load(config.PlanPath, config.PlanExpected)
	if err != nil {
		return stageplan.Binding{}, stagecursor.Cursor{}, nil, err
	}
	prefix := make([]stagereceipt.Verified, 0, len(config.Receipts))
	predecessors := []stagereceipt.Verified{}
	for _, source := range config.Receipts {
		verified, err := stagereceipt.Load(source.Path, source.Digest, plan, predecessors)
		if err != nil {
			return stageplan.Binding{}, stagecursor.Cursor{}, nil, err
		}
		prefix = append(prefix, verified)
		predecessors = []stagereceipt.Verified{verified}
	}
	cursor, err := stagecursor.Evaluate(plan, prefix)
	if err != nil {
		return stageplan.Binding{}, stagecursor.Cursor{}, nil, err
	}
	return plan, cursor, prefix, nil
}
