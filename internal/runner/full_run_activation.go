package runner

import (
	"context"
	"errors"
	"sync"
)

const FullRunExecutionActivationReceiptFormat = "ok147-full-run-execution-activation-receipt/v1"

// FullRunExecutionActivationReceipt is the common redaction-safe result used
// by local and future Job activation adapters. It contains no credentials,
// endpoints, runtime target identity or private paths.
type FullRunExecutionActivationReceipt struct {
	Format    string                          `json:"format"`
	State     string                          `json:"state"`
	Manifest  FullRunExecutionManifestReceipt `json:"manifest"`
	Execution *FullRunOrchestrationReceipt    `json:"execution,omitempty"`
}

type fullRunManifestExecution interface {
	Run(context.Context) (FullRunOrchestrationReceipt, error)
}

type fullRunExecutionActivationFactories struct {
	open func(string, FullRunExecutionManifestRuntime) (fullRunManifestExecution, FullRunExecutionManifestReceipt, error)
}

// FullRunExecutionActivation is the single shared manifest-to-run boundary
// for a local adapter and an ephemeral Job adapter. Open remains inert; Run is
// single-use and delegates exactly once to the already bounded Stage 1-12
// executor. It adds no retry, rollback or cleanup surface.
type FullRunExecutionActivation struct {
	execution fullRunManifestExecution
	manifest  FullRunExecutionManifestReceipt

	mu   sync.Mutex
	used bool
}

// OpenFullRunExecutionActivation verifies and opens one private full-run
// manifest without contacting an authority or executing a stage.
func OpenFullRunExecutionActivation(path string, runtime FullRunExecutionManifestRuntime) (*FullRunExecutionActivation, FullRunExecutionActivationReceipt, error) {
	return openFullRunExecutionActivation(path, runtime, defaultFullRunExecutionActivationFactories())
}

func openFullRunExecutionActivation(path string, runtime FullRunExecutionManifestRuntime, factories fullRunExecutionActivationFactories) (*FullRunExecutionActivation, FullRunExecutionActivationReceipt, error) {
	receipt := FullRunExecutionActivationReceipt{
		Format: FullRunExecutionActivationReceiptFormat,
		State:  "STOPPED",
	}
	if factories.open == nil {
		return nil, receipt, errors.New("full-run activation factory is incomplete")
	}
	execution, manifest, err := factories.open(path, runtime)
	receipt.Manifest = manifest
	if err != nil || execution == nil || manifest.Format != FullRunExecutionManifestReceiptFormat || manifest.State != "VERIFIED" || manifest.MutationAllowed {
		return nil, receipt, errors.New("open verified full-run activation")
	}
	receipt.State = "PREPARED"
	return &FullRunExecutionActivation{execution: execution, manifest: manifest}, receipt, nil
}

// Run consumes the prepared activation before invoking the concrete executor.
// A stopped concrete receipt is preserved exactly for durable evidence.
func (activation *FullRunExecutionActivation) Run(ctx context.Context) (FullRunExecutionActivationReceipt, error) {
	receipt := FullRunExecutionActivationReceipt{
		Format: FullRunExecutionActivationReceiptFormat,
		State:  "STOPPED",
	}
	if activation == nil {
		return receipt, errors.New("full-run activation is unavailable")
	}
	activation.mu.Lock()
	if activation.used || activation.execution == nil {
		activation.mu.Unlock()
		return receipt, errors.New("full-run activation is already consumed")
	}
	activation.used = true
	receipt.Manifest = activation.manifest
	execution := activation.execution
	activation.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return receipt, errors.New("full-run activation context is unavailable")
	}
	executed, err := execution.Run(ctx)
	receipt.Execution = &executed
	if err != nil {
		if executed.State == "STOPPED" {
			receipt.State = "STOPPED"
		}
		return receipt, err
	}
	if executed.Format != FullRunOrchestrationReceiptFormat || executed.State != "SUCCEEDED" || executed.StoppedAt != "" {
		receipt.State = "STOPPED"
		return receipt, errors.New("full-run execution returned an invalid success receipt")
	}
	receipt.State = "SUCCEEDED"
	return receipt, nil
}

func defaultFullRunExecutionActivationFactories() fullRunExecutionActivationFactories {
	return fullRunExecutionActivationFactories{
		open: func(path string, runtime FullRunExecutionManifestRuntime) (fullRunManifestExecution, FullRunExecutionManifestReceipt, error) {
			return OpenFullRunExecutionManifest(path, runtime)
		},
	}
}
