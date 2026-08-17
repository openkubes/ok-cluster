package runner

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/openkubes/ok-cluster/internal/execution"
)

func TestPostRuntimeOrchestrationRunsExactFiveStageSuffixOnce(t *testing.T) {
	var calls []string
	handoff := &VerifiedTargetCredentialStageHandoff{verified: true}
	orchestration := PostRuntimeOrchestration{
		RunTargetCredential: func(context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error) {
			calls = append(calls, "target-credential")
			return postRuntimeStagedReceipt("target-credential", "1"), handoff, nil
		},
		RunTargetRegistration: func(_ context.Context, got *VerifiedTargetCredentialStageHandoff, predecessor execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
			calls = append(calls, "target-registration")
			if got != handoff || predecessor.StageID != "target-credential" {
				t.Fatal("target-credential handoff was not passed only to registration")
			}
			return postRuntimeStagedReceipt("target-registration", "2"), nil
		},
		RunPlatformApplications: func(_ context.Context, predecessor execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
			calls = append(calls, "platform-applications")
			if predecessor.StageID != "target-registration" {
				t.Fatal("registration receipt was not passed to platform Applications")
			}
			return postRuntimeStagedReceipt("platform-applications", "3"), nil
		},
		RunPlatformObservation: func(_ context.Context, predecessor execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
			calls = append(calls, "platform-observation")
			if predecessor.StageID != "platform-applications" {
				t.Fatal("Application receipt was not passed to platform observation")
			}
			return postRuntimeObservationReceipt("4"), nil
		},
		RunAggregateEvidence: func(_ context.Context, predecessor execution.ObservationStageRunReceipt) (execution.EvaluationStageRunReceipt, error) {
			calls = append(calls, "aggregate-evidence")
			if predecessor.StageID != "platform-observation" {
				t.Fatal("platform observation receipt was not passed to aggregate evidence")
			}
			return postRuntimeEvaluationReceipt("5"), nil
		},
	}
	receipt, err := orchestration.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != PostRuntimeOrchestrationReceiptFormat || receipt.State != "SUCCEEDED" || receipt.StoppedAt != "" || receipt.PlanDigest != runnerStageSHA("a") || len(receipt.Checkpoints) != 5 {
		t.Fatalf("unexpected post-runtime receipt: %#v", receipt)
	}
	if !reflect.DeepEqual(calls, postRuntimeStageOrder) {
		t.Fatalf("post-runtime order differs: %v", calls)
	}
	if !handoff.consumed {
		t.Fatal("unused in-memory credential handoff survived orchestration")
	}
	for index, checkpoint := range receipt.Checkpoints {
		if checkpoint.StageID != postRuntimeStageOrder[index] || checkpoint.State != "COMPLETED_SUCCEEDED" || checkpoint.StageReceiptDigest == "" {
			t.Fatalf("unexpected checkpoint %d: %#v", index, checkpoint)
		}
	}
}

func TestPostRuntimeOrchestrationStopsWithoutRetryAndDiscardsCredential(t *testing.T) {
	for name, stopStage := range map[string]string{
		"credential error":   "target-credential",
		"registration error": "target-registration",
		"application error":  "platform-applications",
		"observation error":  "platform-observation",
		"evaluation error":   "aggregate-evidence",
	} {
		t.Run(name, func(t *testing.T) {
			calls := map[string]int{}
			handoff := &VerifiedTargetCredentialStageHandoff{verified: true}
			orchestration := PostRuntimeOrchestration{
				RunTargetCredential: func(context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error) {
					calls["target-credential"]++
					if stopStage == "target-credential" {
						return execution.StagedOperationReceipt{}, handoff, errors.New("private failure")
					}
					return postRuntimeStagedReceipt("target-credential", "1"), handoff, nil
				},
				RunTargetRegistration: func(context.Context, *VerifiedTargetCredentialStageHandoff, execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
					calls["target-registration"]++
					if stopStage == "target-registration" {
						return execution.StagedOperationReceipt{}, errors.New("private failure")
					}
					return postRuntimeStagedReceipt("target-registration", "2"), nil
				},
				RunPlatformApplications: func(context.Context, execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
					calls["platform-applications"]++
					if stopStage == "platform-applications" {
						return execution.StagedOperationReceipt{}, errors.New("private failure")
					}
					return postRuntimeStagedReceipt("platform-applications", "3"), nil
				},
				RunPlatformObservation: func(context.Context, execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
					calls["platform-observation"]++
					if stopStage == "platform-observation" {
						return execution.ObservationStageRunReceipt{}, errors.New("private failure")
					}
					return postRuntimeObservationReceipt("4"), nil
				},
				RunAggregateEvidence: func(context.Context, execution.ObservationStageRunReceipt) (execution.EvaluationStageRunReceipt, error) {
					calls["aggregate-evidence"]++
					if stopStage == "aggregate-evidence" {
						return execution.EvaluationStageRunReceipt{}, errors.New("private failure")
					}
					return postRuntimeEvaluationReceipt("5"), nil
				},
			}
			receipt, err := orchestration.Run(context.Background())
			if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != stopStage {
				t.Fatalf("orchestration did not stop at %s: %#v %v", stopStage, receipt, err)
			}
			stopIndex := -1
			for index, stage := range postRuntimeStageOrder {
				if stage == stopStage {
					stopIndex = index
					break
				}
			}
			for index, stage := range postRuntimeStageOrder {
				want := 0
				if index <= stopIndex {
					want = 1
				}
				if calls[stage] != want {
					t.Fatalf("stage %s calls=%d want=%d; all=%v", stage, calls[stage], want, calls)
				}
			}
			if !handoff.consumed {
				t.Fatal("credential handoff survived stopped orchestration")
			}
		})
	}
}

func TestPostRuntimeOrchestrationRejectsMalformedOrForeignReceipts(t *testing.T) {
	for name, mutate := range map[string]func(*execution.StagedOperationReceipt){
		"wrong format": func(receipt *execution.StagedOperationReceipt) {
			receipt.Format = execution.ObservationStageReceiptFormat
		},
		"wrong stage":  func(receipt *execution.StagedOperationReceipt) { receipt.StageID = "platform-applications" },
		"foreign plan": func(receipt *execution.StagedOperationReceipt) { receipt.PlanDigest = runnerStageSHA("f") },
		"failed state": func(receipt *execution.StagedOperationReceipt) { receipt.State = "COMPLETED_FAILED" },
		"bad digest":   func(receipt *execution.StagedOperationReceipt) { receipt.StageReceiptDigest = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			orchestration := successfulPostRuntimeOrchestration()
			base := orchestration.RunTargetRegistration
			orchestration.RunTargetRegistration = func(ctx context.Context, handoff *VerifiedTargetCredentialStageHandoff, predecessor execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
				receipt, err := base(ctx, handoff, predecessor)
				mutate(&receipt)
				return receipt, err
			}
			receipt, err := orchestration.Run(context.Background())
			if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "target-registration" || len(receipt.Checkpoints) != 1 {
				t.Fatalf("malformed receipt was accepted: %#v %v", receipt, err)
			}
		})
	}
}

func TestPostRuntimeOrchestrationRequiresCompleteLiveContext(t *testing.T) {
	if receipt, err := (PostRuntimeOrchestration{}).Run(context.Background()); err == nil || receipt.State != "STOPPED" {
		t.Fatalf("incomplete orchestration was accepted: %#v %v", receipt, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	orchestration := successfulPostRuntimeOrchestration()
	orchestration.RunTargetCredential = func(context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error) {
		calls++
		return postRuntimeStagedReceipt("target-credential", "1"), &VerifiedTargetCredentialStageHandoff{verified: true}, nil
	}
	if receipt, err := orchestration.Run(cancelled); err == nil || receipt.StoppedAt != "target-credential" || calls != 0 {
		t.Fatalf("cancelled orchestration invoked a stage: %#v calls=%d err=%v", receipt, calls, err)
	}

	runtimeContext, stop := context.WithCancel(context.Background())
	orchestration = successfulPostRuntimeOrchestration()
	registrationCalls := 0
	orchestration.RunTargetCredential = func(context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error) {
		stop()
		return postRuntimeStagedReceipt("target-credential", "1"), &VerifiedTargetCredentialStageHandoff{verified: true}, nil
	}
	orchestration.RunTargetRegistration = func(context.Context, *VerifiedTargetCredentialStageHandoff, execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
		registrationCalls++
		return postRuntimeStagedReceipt("target-registration", "2"), nil
	}
	if receipt, err := orchestration.Run(runtimeContext); err == nil || receipt.StoppedAt != "target-registration" || len(receipt.Checkpoints) != 1 || registrationCalls != 0 {
		t.Fatalf("cancelled suffix invoked a later stage: %#v registrationCalls=%d err=%v", receipt, registrationCalls, err)
	}
}

func successfulPostRuntimeOrchestration() PostRuntimeOrchestration {
	return PostRuntimeOrchestration{
		RunTargetCredential: func(context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error) {
			return postRuntimeStagedReceipt("target-credential", "1"), &VerifiedTargetCredentialStageHandoff{verified: true}, nil
		},
		RunTargetRegistration: func(context.Context, *VerifiedTargetCredentialStageHandoff, execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
			return postRuntimeStagedReceipt("target-registration", "2"), nil
		},
		RunPlatformApplications: func(context.Context, execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
			return postRuntimeStagedReceipt("platform-applications", "3"), nil
		},
		RunPlatformObservation: func(context.Context, execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
			return postRuntimeObservationReceipt("4"), nil
		},
		RunAggregateEvidence: func(context.Context, execution.ObservationStageRunReceipt) (execution.EvaluationStageRunReceipt, error) {
			return postRuntimeEvaluationReceipt("5"), nil
		},
	}
}

func postRuntimeStagedReceipt(stageID, digestValue string) execution.StagedOperationReceipt {
	return execution.StagedOperationReceipt{
		Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: runnerStageSHA("a"),
		StageID: stageID, StageReceiptDigest: runnerStageSHA(digestValue),
	}
}

func postRuntimeObservationReceipt(digestValue string) execution.ObservationStageRunReceipt {
	return execution.ObservationStageRunReceipt{
		Format: execution.ObservationStageReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: runnerStageSHA("a"),
		StageID: "platform-observation", StageReceiptDigest: runnerStageSHA(digestValue),
	}
}

func postRuntimeEvaluationReceipt(digestValue string) execution.EvaluationStageRunReceipt {
	return execution.EvaluationStageRunReceipt{
		Format: execution.EvaluationStageReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: runnerStageSHA("a"),
		StageID: "aggregate-evidence", StageReceiptDigest: runnerStageSHA(digestValue),
	}
}
