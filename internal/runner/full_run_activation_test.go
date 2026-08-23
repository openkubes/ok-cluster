package runner

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestFullRunExecutionActivationIsInertThenRunsExactlyOnce(t *testing.T) {
	execution := &recordingFullRunManifestExecution{
		receipt: successfulFullRunActivationExecutionReceipt(),
	}
	factories := fullRunExecutionActivationFactories{
		open: func(path string, _ FullRunExecutionManifestRuntime) (fullRunManifestExecution, FullRunExecutionManifestReceipt, error) {
			if path != "/private/full-run.json" {
				t.Fatalf("activation path differs: %q", path)
			}
			return execution, verifiedFullRunActivationManifestReceipt(), nil
		},
	}
	activation, prepared, err := openFullRunExecutionActivation("/private/full-run.json", FullRunExecutionManifestRuntime{}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Format != FullRunExecutionActivationReceiptFormat || prepared.State != "PREPARED" || prepared.Execution != nil || execution.calls.Load() != 0 {
		t.Fatalf("opening activation was not inert: receipt=%#v calls=%d", prepared, execution.calls.Load())
	}

	receipt, err := activation.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != "SUCCEEDED" || receipt.Execution == nil || receipt.Execution.State != "SUCCEEDED" || execution.calls.Load() != 1 {
		t.Fatalf("full-run activation receipt differs: %#v calls=%d", receipt, execution.calls.Load())
	}
	if second, err := activation.Run(context.Background()); err == nil || second.State != "STOPPED" || execution.calls.Load() != 1 {
		t.Fatalf("consumed activation ran again: receipt=%#v calls=%d err=%v", second, execution.calls.Load(), err)
	}
}

func TestFullRunExecutionActivationPreservesStoppedExecution(t *testing.T) {
	stopped := successfulFullRunActivationExecutionReceipt()
	stopped.State = "STOPPED"
	stopped.StoppedAt = "network-observation"
	stopped.Checkpoints = stopped.Checkpoints[:4]
	expectedErr := errors.New("bounded stage stopped")
	execution := &recordingFullRunManifestExecution{receipt: stopped, err: expectedErr}
	activation, _, err := openFullRunExecutionActivation("/private/full-run.json", FullRunExecutionManifestRuntime{}, fullRunExecutionActivationFactories{
		open: func(string, FullRunExecutionManifestRuntime) (fullRunManifestExecution, FullRunExecutionManifestReceipt, error) {
			return execution, verifiedFullRunActivationManifestReceipt(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := activation.Run(context.Background())
	if !errors.Is(err, expectedErr) || receipt.State != "STOPPED" || receipt.Execution == nil || !reflect.DeepEqual(*receipt.Execution, stopped) {
		t.Fatalf("stopped execution was not preserved: receipt=%#v err=%v", receipt, err)
	}
}

func TestFullRunExecutionActivationAcceptsAttemptBoundManifestReceipt(t *testing.T) {
	execution := &recordingFullRunManifestExecution{receipt: successfulFullRunActivationExecutionReceipt()}
	receipt := verifiedFullRunActivationManifestReceipt()
	receipt.Format = FullRunExecutionManifestReceiptFormatV2
	receipt.ExecutionAttemptDigest = runnerStageSHA("2")
	activation, prepared, err := openFullRunExecutionActivation("/private/full-run-v4.json", FullRunExecutionManifestRuntime{}, fullRunExecutionActivationFactories{
		open: func(string, FullRunExecutionManifestRuntime) (fullRunManifestExecution, FullRunExecutionManifestReceipt, error) {
			return execution, receipt, nil
		},
	})
	if err != nil || activation == nil || prepared.State != "PREPARED" || prepared.Manifest != receipt {
		t.Fatalf("attempt-bound activation was rejected: activation=%#v receipt=%#v err=%v", activation, prepared, err)
	}
}

func TestFullRunExecutionActivationRetainsRedactedPostPrefixReceipt(t *testing.T) {
	execution := &recordingFullRunManifestExecution{receipt: successfulFullRunActivationExecutionReceipt()}
	postPrefix := ObservabilityCollectorPostPrefixReceipt{
		Format: ObservabilityCollectorPostPrefixReceiptFormat, State: "ACTIVATED",
		PackageDigest: runnerStageSHA("1"), RuntimeBindingDigest: runnerStageSHA("2"), TargetIdentityDigest: runnerStageSHA("3"),
		RuntimeAuthorityPackageDigest: runnerStageSHA("4"), RuntimeAuthorityReceiptDigest: runnerStageSHA("5"), RuntimeAuthorityCreatedObjects: 5,
		ObserverCredentialReceiptDigest: runnerStageSHA("6"), CredentialReceiptDigest: runnerStageSHA("a"),
		LaunchState: "ACTIVATED", CreatedObjects: 4,
	}
	activation := &FullRunExecutionActivation{
		execution: execution, manifest: verifiedFullRunActivationManifestReceipt(),
		postPrefixReceipt: func() ObservabilityCollectorPostPrefixReceipt { return postPrefix },
	}
	receipt, err := activation.Run(context.Background())
	if err != nil || receipt.State != "SUCCEEDED" || receipt.PostPrefix == nil || !reflect.DeepEqual(*receipt.PostPrefix, postPrefix) {
		t.Fatalf("post-prefix receipt was not retained: %#v err=%v", receipt, err)
	}
	raw, err := json.Marshal(receipt)
	if err != nil || strings.Contains(strings.ToLower(string(raw)), "token") || strings.Contains(strings.ToLower(string(raw)), "endpoint") ||
		strings.Contains(strings.ToLower(string(raw)), "kubeconfig") || strings.Contains(strings.ToLower(string(raw)), "certificate") {
		t.Fatalf("post-prefix receipt disclosed private material: %s err=%v", raw, err)
	}
}

func TestFullRunExecutionActivationAllowsOneConcurrentRun(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	execution := &recordingFullRunManifestExecution{
		receipt: successfulFullRunActivationExecutionReceipt(), started: started, release: release,
	}
	activation := &FullRunExecutionActivation{execution: execution, manifest: verifiedFullRunActivationManifestReceipt()}
	var group sync.WaitGroup
	group.Add(2)
	results := make(chan error, 2)
	go func() {
		defer group.Done()
		_, err := activation.Run(context.Background())
		results <- err
	}()
	<-started
	go func() {
		defer group.Done()
		_, err := activation.Run(context.Background())
		results <- err
	}()
	close(release)
	group.Wait()
	close(results)
	succeeded, stopped := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			stopped++
		}
	}
	if succeeded != 1 || stopped != 1 || execution.calls.Load() != 1 {
		t.Fatalf("concurrent activation was not single-use: succeeded=%d stopped=%d calls=%d", succeeded, stopped, execution.calls.Load())
	}
}

func TestFullRunExecutionActivationFailsClosedBeforeExecution(t *testing.T) {
	tests := map[string]func() (*FullRunExecutionActivation, FullRunExecutionActivationReceipt, error){
		"missing factory": func() (*FullRunExecutionActivation, FullRunExecutionActivationReceipt, error) {
			return openFullRunExecutionActivation("/private/full-run.json", FullRunExecutionManifestRuntime{}, fullRunExecutionActivationFactories{})
		},
		"open error": func() (*FullRunExecutionActivation, FullRunExecutionActivationReceipt, error) {
			return openFullRunExecutionActivation("/private/full-run.json", FullRunExecutionManifestRuntime{}, fullRunExecutionActivationFactories{
				open: func(string, FullRunExecutionManifestRuntime) (fullRunManifestExecution, FullRunExecutionManifestReceipt, error) {
					return nil, FullRunExecutionManifestReceipt{}, errors.New("private input rejected")
				},
			})
		},
		"unverified manifest": func() (*FullRunExecutionActivation, FullRunExecutionActivationReceipt, error) {
			return openFullRunExecutionActivation("/private/full-run.json", FullRunExecutionManifestRuntime{}, fullRunExecutionActivationFactories{
				open: func(string, FullRunExecutionManifestRuntime) (fullRunManifestExecution, FullRunExecutionManifestReceipt, error) {
					receipt := verifiedFullRunActivationManifestReceipt()
					receipt.State = "STOPPED"
					return &recordingFullRunManifestExecution{}, receipt, nil
				},
			})
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			activation, receipt, err := run()
			if err == nil || activation != nil || receipt.State != "STOPPED" || receipt.Execution != nil {
				t.Fatalf("unsafe activation was accepted: activation=%#v receipt=%#v err=%v", activation, receipt, err)
			}
		})
	}

	execution := &recordingFullRunManifestExecution{receipt: successfulFullRunActivationExecutionReceipt()}
	activation := &FullRunExecutionActivation{execution: execution, manifest: verifiedFullRunActivationManifestReceipt()}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if receipt, err := activation.Run(cancelled); err == nil || receipt.State != "STOPPED" || execution.calls.Load() != 0 {
		t.Fatalf("cancelled activation reached execution: receipt=%#v calls=%d err=%v", receipt, execution.calls.Load(), err)
	}
}

func TestFullRunExecutionActivationReceiptIsRedactionSafe(t *testing.T) {
	receipt := FullRunExecutionActivationReceipt{
		Format:   FullRunExecutionActivationReceiptFormat,
		State:    "PREPARED",
		Manifest: verifiedFullRunActivationManifestReceipt(),
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"/private/", "token", "endpoint", "kubeconfig", "certificate", "targetidentity"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("activation receipt disclosed %q: %s", forbidden, raw)
		}
	}
}

type recordingFullRunManifestExecution struct {
	calls   atomic.Int32
	receipt FullRunOrchestrationReceipt
	err     error
	started chan struct{}
	release chan struct{}
}

func (execution *recordingFullRunManifestExecution) Run(context.Context) (FullRunOrchestrationReceipt, error) {
	execution.calls.Add(1)
	if execution.started != nil {
		close(execution.started)
	}
	if execution.release != nil {
		<-execution.release
	}
	return execution.receipt, execution.err
}

func verifiedFullRunActivationManifestReceipt() FullRunExecutionManifestReceipt {
	return FullRunExecutionManifestReceipt{
		Format: FullRunExecutionManifestReceiptFormat, State: "VERIFIED",
		ManifestDigest: runnerStageSHA("a"), PlanDigest: runnerStageSHA("b"),
		ProjectionManifestDigest: runnerStageSHA("c"), ProjectionAuthorityDigest: runnerStageSHA("d"),
		NetworkProfileDigest: runnerStageSHA("e"), PlatformProfileDigest: runnerStageSHA("f"),
		AggregateProfileDigest: runnerStageSHA("1"), RuntimeIdentityMode: "lifecycle-derived-private/v1",
		AuthorizationMode: "predecessor-bound-tls/v1", CapabilityMode: "runtime-bound-in-memory/v1",
	}
}

func successfulFullRunActivationExecutionReceipt() FullRunOrchestrationReceipt {
	stages := append(append([]string(nil), preRuntimeStageOrder...), postRuntimeStageOrder...)
	receipt := FullRunOrchestrationReceipt{
		Format: FullRunOrchestrationReceiptFormat, State: "SUCCEEDED", PlanDigest: runnerStageSHA("b"),
		Checkpoints: make([]FullRunStageCheckpoint, 0, len(stages)),
	}
	for index, stageID := range stages {
		receipt.Checkpoints = append(receipt.Checkpoints, FullRunStageCheckpoint{
			StageID: stageID, State: "COMPLETED_SUCCEEDED", StageReceiptDigest: runnerStageSHA(string(rune('a' + index%6))),
		})
	}
	return receipt
}
