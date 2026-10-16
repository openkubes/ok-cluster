package stageplan

import (
	"encoding/json"
	"errors"
)

// BuildBareCluster constructs an ordinary NO-GO plan from independently
// verified input digests. It does not invent runtime outcomes, attempts,
// authorization, recovery identities or a relaxed observation mode.
func BuildBareCluster(expected Expected, inputs map[string]string) ([]byte, Binding, error) {
	if expected.CompletionMode != CompletionModeBareClusterMVP || expected.ExecutionAttemptDigest != "" ||
		expected.RecoverySourcePlanDigest != "" || expected.NetworkObservationMode != "" {
		return nil, Binding{}, errors.New("fresh Bare-MVP plan requires ordinary seven-stage scope and full network observation")
	}
	if err := ValidateExpected(expected); err != nil {
		return nil, Binding{}, err
	}
	names := [][]string{
		{"projection.provider-prerequisites"}, {"projection.cluster-lifecycle", "stage.provider-access"},
		{"stage.lifecycle-observation"}, {"stage.enablement"}, {"stage.network-observation"},
		{"stage.runtime-binding"}, {"stage.target-access"},
	}
	if len(inputs) != 8 {
		return nil, Binding{}, errors.New("fresh Bare-MVP plan requires exactly eight immutable inputs")
	}
	stages := make([]Stage, BareClusterStageCount)
	for i, rule := range requiredSequence[:BareClusterStageCount] {
		stage := Stage{ID: rule.id, Order: i + 1, Kind: rule.kind, Authority: rule.authority,
			GrantOperation: rule.grantOperation, Requires: append([]string{}, rule.requires...)}
		for _, name := range names[i] {
			value, found := inputs[name]
			if !found || !digestPattern.MatchString(value) {
				return nil, Binding{}, errors.New("fresh Bare-MVP plan input is missing or invalid")
			}
			stage.Inputs = append(stage.Inputs, Input{Name: name, Digest: value})
		}
		stages[i] = stage
	}
	doc := document{Format: Format, ContractIdentity: expected.ContractIdentity, IntentRevision: expected.IntentRevision,
		EnablementRevision: expected.EnablementRevision, PlatformRevision: expected.PlatformRevision,
		ExecutionFixture: expected.ExecutionFixture, AuthorizationState: "NO-GO", CompletionMode: CompletionModeBareClusterMVP,
		Authorities: Authorities{Infrastructure: expected.InfrastructureAuthority, Management: expected.ManagementAuthority,
			GitOps: expected.GitOpsAuthority, WorkloadIdentityMode: "capi-cluster-uid/v1", RunnerIdentityMode: "bounded-job/v1"}, Stages: stages}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, Binding{}, err
	}
	raw = append(raw, '\n')
	binding, err := Verify(raw, expected)
	if err != nil {
		return nil, Binding{}, err
	}
	return raw, binding, nil
}
