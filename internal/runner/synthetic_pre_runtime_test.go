package runner

import "github.com/openkubes/ok-cluster/internal/projection"

// Synthetic orchestration fixture ONLY. It deliberately does not call an
// execution opener or approve a resolver. All stage/authorization factories
// used by these tests are local fakes. Production openers are tested separately
// for unconditional denial of every non-nil workload resolver.
func openSyntheticPreRuntimeExecution(config PreRuntimeExecutionConfig, factories preRuntimeExecutionFactories) (*PreRuntimeExecution, error) {
	initial, err := validatePreRuntimeExecutionStructure(config, factories)
	if err != nil {
		return nil, err
	}
	config.TargetAccess.ExpectedObjects = append([]projection.ResourceIdentity(nil), config.TargetAccess.ExpectedObjects...)
	return &PreRuntimeExecution{config: config, initial: initial, factories: factories}, nil
}
