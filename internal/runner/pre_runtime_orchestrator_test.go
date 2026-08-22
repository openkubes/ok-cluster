package runner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/execution"
)

func TestPreRuntimeOrchestrationRunsExactSevenStagePrefixOnce(t *testing.T) {
	var calls []string
	orchestration := successfulPreRuntimeOrchestration(&calls)
	receipt, err := orchestration.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != PreRuntimeOrchestrationReceiptFormat || receipt.State != "SUCCEEDED" || receipt.StoppedAt != "" || receipt.PlanDigest != runnerStageSHA("a") || len(receipt.Checkpoints) != 7 {
		t.Fatalf("unexpected pre-runtime receipt: %#v", receipt)
	}
	if !reflect.DeepEqual(calls, preRuntimeStageOrder) {
		t.Fatalf("pre-runtime order differs: %v", calls)
	}
	for index, checkpoint := range receipt.Checkpoints {
		if checkpoint.StageID != preRuntimeStageOrder[index] || checkpoint.State != "COMPLETED_SUCCEEDED" || checkpoint.StageReceiptDigest == "" {
			t.Fatalf("unexpected checkpoint %d: %#v", index, checkpoint)
		}
	}
}

func TestPreRuntimeOrchestrationPassesOnlyDirectPredecessor(t *testing.T) {
	orchestration := successfulPreRuntimeOrchestration(nil)
	orchestration.RunClusterLifecycle = func(_ context.Context, predecessor execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
		if predecessor.StageID != "provider-prerequisites" {
			t.Fatal("provider receipt was not passed to lifecycle")
		}
		return preRuntimeStagedReceipt("cluster-lifecycle", "2"), nil
	}
	orchestration.RunLifecycleObservation = func(_ context.Context, predecessor execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
		if predecessor.StageID != "cluster-lifecycle" {
			t.Fatal("lifecycle receipt was not passed to lifecycle observation")
		}
		return preRuntimeObservationReceipt("lifecycle-observation", "3"), nil
	}
	orchestration.RunEnablement = func(_ context.Context, predecessor execution.ObservationStageRunReceipt) (execution.StagedOperationReceipt, error) {
		if predecessor.StageID != "lifecycle-observation" {
			t.Fatal("lifecycle observation receipt was not passed to enablement")
		}
		return preRuntimeStagedReceipt("enablement", "4"), nil
	}
	orchestration.RunNetworkObservation = func(_ context.Context, predecessor execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
		if predecessor.StageID != "enablement" {
			t.Fatal("enablement receipt was not passed to network observation")
		}
		return preRuntimeObservationReceipt("network-observation", "5"), nil
	}
	orchestration.RunRuntimeBinding = func(_ context.Context, predecessor execution.ObservationStageRunReceipt) (execution.BindingStageRunReceipt, error) {
		if predecessor.StageID != "network-observation" {
			t.Fatal("network observation receipt was not passed to runtime binding")
		}
		return preRuntimeBindingReceipt("6"), nil
	}
	orchestration.RunTargetAccess = func(_ context.Context, predecessor execution.BindingStageRunReceipt) (execution.StagedOperationReceipt, error) {
		if predecessor.StageID != "runtime-binding" {
			t.Fatal("runtime binding receipt was not passed to target access")
		}
		return preRuntimeStagedReceipt("target-access", "7"), nil
	}
	if _, err := orchestration.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPreRuntimeOrchestrationStopsWithoutRetry(t *testing.T) {
	for _, stopStage := range preRuntimeStageOrder {
		t.Run(stopStage, func(t *testing.T) {
			calls := []string{}
			orchestration := successfulPreRuntimeOrchestration(&calls)
			switch stopStage {
			case "provider-prerequisites":
				orchestration.RunProviderPrerequisites = func(context.Context) (execution.StagedOperationReceipt, error) {
					calls = append(calls, stopStage)
					return execution.StagedOperationReceipt{}, errors.New("private failure")
				}
			case "cluster-lifecycle":
				orchestration.RunClusterLifecycle = func(context.Context, execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
					calls = append(calls, stopStage)
					return execution.StagedOperationReceipt{}, errors.New("private failure")
				}
			case "lifecycle-observation":
				orchestration.RunLifecycleObservation = func(context.Context, execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
					calls = append(calls, stopStage)
					return execution.ObservationStageRunReceipt{}, errors.New("private failure")
				}
			case "enablement":
				orchestration.RunEnablement = func(context.Context, execution.ObservationStageRunReceipt) (execution.StagedOperationReceipt, error) {
					calls = append(calls, stopStage)
					return execution.StagedOperationReceipt{}, errors.New("private failure")
				}
			case "network-observation":
				orchestration.RunNetworkObservation = func(context.Context, execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
					calls = append(calls, stopStage)
					return execution.ObservationStageRunReceipt{}, errors.New("private failure")
				}
			case "runtime-binding":
				orchestration.RunRuntimeBinding = func(context.Context, execution.ObservationStageRunReceipt) (execution.BindingStageRunReceipt, error) {
					calls = append(calls, stopStage)
					return execution.BindingStageRunReceipt{}, errors.New("private failure")
				}
			case "target-access":
				orchestration.RunTargetAccess = func(context.Context, execution.BindingStageRunReceipt) (execution.StagedOperationReceipt, error) {
					calls = append(calls, stopStage)
					return execution.StagedOperationReceipt{}, errors.New("private failure")
				}
			}
			receipt, err := orchestration.Run(context.Background())
			if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != stopStage {
				t.Fatalf("orchestration did not stop at %s: %#v %v", stopStage, receipt, err)
			}
			stopIndex := stageIndex(preRuntimeStageOrder, stopStage)
			if len(calls) != stopIndex+1 || !reflect.DeepEqual(calls, preRuntimeStageOrder[:stopIndex+1]) {
				t.Fatalf("stages were retried or invoked after stop: %v", calls)
			}
		})
	}
}

func TestPreRuntimeOrchestrationPreservesProviderFailureCause(t *testing.T) {
	orchestration := successfulPreRuntimeOrchestration(nil)
	orchestration.RunProviderPrerequisites = func(context.Context) (execution.StagedOperationReceipt, error) {
		return execution.StagedOperationReceipt{}, errors.New("safe provider authorization cause")
	}
	receipt, err := orchestration.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "provider-prerequisites" ||
		!strings.Contains(err.Error(), "safe provider authorization cause") {
		t.Fatalf("provider failure cause was not preserved: %#v err=%v", receipt, err)
	}
}

func TestPreRuntimeOrchestrationRejectsMalformedAndForeignReceipts(t *testing.T) {
	for name, mutate := range map[string]func(*execution.ObservationStageRunReceipt){
		"wrong format": func(receipt *execution.ObservationStageRunReceipt) { receipt.Format = execution.StagedReceiptFormat },
		"wrong stage":  func(receipt *execution.ObservationStageRunReceipt) { receipt.StageID = "enablement" },
		"foreign plan": func(receipt *execution.ObservationStageRunReceipt) { receipt.PlanDigest = runnerStageSHA("f") },
		"failed state": func(receipt *execution.ObservationStageRunReceipt) { receipt.State = "COMPLETED_FAILED" },
		"bad digest":   func(receipt *execution.ObservationStageRunReceipt) { receipt.StageReceiptDigest = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			orchestration := successfulPreRuntimeOrchestration(nil)
			orchestration.RunNetworkObservation = func(context.Context, execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
				receipt := preRuntimeObservationReceipt("network-observation", "5")
				mutate(&receipt)
				return receipt, nil
			}
			receipt, err := orchestration.Run(context.Background())
			if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "network-observation" || len(receipt.Checkpoints) != 4 {
				t.Fatalf("malformed receipt was accepted: %#v %v", receipt, err)
			}
		})
	}
}

func TestPreRuntimeOrchestrationRequiresCompleteLiveContext(t *testing.T) {
	if receipt, err := (PreRuntimeOrchestration{}).Run(context.Background()); err == nil || receipt.State != "STOPPED" {
		t.Fatalf("incomplete orchestration was accepted: %#v %v", receipt, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	calls := []string{}
	orchestration := successfulPreRuntimeOrchestration(&calls)
	if receipt, err := orchestration.Run(cancelled); err == nil || receipt.StoppedAt != "provider-prerequisites" || len(calls) != 0 {
		t.Fatalf("cancelled orchestration invoked a stage: %#v calls=%v err=%v", receipt, calls, err)
	}

	runtimeContext, stop := context.WithCancel(context.Background())
	orchestration = successfulPreRuntimeOrchestration(nil)
	lifecycleCalls := 0
	orchestration.RunProviderPrerequisites = func(context.Context) (execution.StagedOperationReceipt, error) {
		stop()
		return preRuntimeStagedReceipt("provider-prerequisites", "1"), nil
	}
	orchestration.RunClusterLifecycle = func(context.Context, execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
		lifecycleCalls++
		return preRuntimeStagedReceipt("cluster-lifecycle", "2"), nil
	}
	if receipt, err := orchestration.Run(runtimeContext); err == nil || receipt.StoppedAt != "cluster-lifecycle" || len(receipt.Checkpoints) != 1 || lifecycleCalls != 0 {
		t.Fatalf("cancelled prefix invoked a later stage: %#v lifecycleCalls=%d err=%v", receipt, lifecycleCalls, err)
	}
}

func successfulPreRuntimeOrchestration(calls *[]string) PreRuntimeOrchestration {
	record := func(stage string) {
		if calls != nil {
			*calls = append(*calls, stage)
		}
	}
	return PreRuntimeOrchestration{
		RunProviderPrerequisites: func(context.Context) (execution.StagedOperationReceipt, error) {
			record("provider-prerequisites")
			return preRuntimeStagedReceipt("provider-prerequisites", "1"), nil
		},
		RunClusterLifecycle: func(context.Context, execution.StagedOperationReceipt) (execution.StagedOperationReceipt, error) {
			record("cluster-lifecycle")
			return preRuntimeStagedReceipt("cluster-lifecycle", "2"), nil
		},
		RunLifecycleObservation: func(context.Context, execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
			record("lifecycle-observation")
			return preRuntimeObservationReceipt("lifecycle-observation", "3"), nil
		},
		RunEnablement: func(context.Context, execution.ObservationStageRunReceipt) (execution.StagedOperationReceipt, error) {
			record("enablement")
			return preRuntimeStagedReceipt("enablement", "4"), nil
		},
		RunNetworkObservation: func(context.Context, execution.StagedOperationReceipt) (execution.ObservationStageRunReceipt, error) {
			record("network-observation")
			return preRuntimeObservationReceipt("network-observation", "5"), nil
		},
		RunRuntimeBinding: func(context.Context, execution.ObservationStageRunReceipt) (execution.BindingStageRunReceipt, error) {
			record("runtime-binding")
			return preRuntimeBindingReceipt("6"), nil
		},
		RunTargetAccess: func(context.Context, execution.BindingStageRunReceipt) (execution.StagedOperationReceipt, error) {
			record("target-access")
			return preRuntimeStagedReceipt("target-access", "7"), nil
		},
	}
}

func preRuntimeStagedReceipt(stageID, digestValue string) execution.StagedOperationReceipt {
	return execution.StagedOperationReceipt{
		Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: runnerStageSHA("a"),
		StageID: stageID, StageReceiptDigest: runnerStageSHA(digestValue),
	}
}

func preRuntimeObservationReceipt(stageID, digestValue string) execution.ObservationStageRunReceipt {
	return execution.ObservationStageRunReceipt{
		Format: execution.ObservationStageReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: runnerStageSHA("a"),
		StageID: stageID, StageReceiptDigest: runnerStageSHA(digestValue),
	}
}

func preRuntimeBindingReceipt(digestValue string) execution.BindingStageRunReceipt {
	return execution.BindingStageRunReceipt{
		Format: execution.BindingStageReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: runnerStageSHA("a"),
		StageID: "runtime-binding", StageReceiptDigest: runnerStageSHA(digestValue),
	}
}

func stageIndex(stages []string, target string) int {
	for index, stage := range stages {
		if stage == target {
			return index
		}
	}
	return -1
}
