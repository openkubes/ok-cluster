package runner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestFirstRunPlatformCapabilityResolverBindsAndConsumesExactProbeOnce(t *testing.T) {
	profile := runnerPlatformProfile()
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: profile.IntentRevision,
		EnablementRevision: digestOf("e"), PlatformRevision: profile.PlatformRevision,
		TargetClusterUID: "cluster-uid-disposable-ok147", Required: []string{"PlatformReady"},
	}
	probe := &recordingPlatformCapabilityProbe{result: PlatformCapabilityProbeResult{Passed: true}}
	clock := func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) }
	resolver, err := NewFirstRunPlatformCapabilityResolver(probe, clock)
	if err != nil {
		t.Fatal(err)
	}
	source, err := resolver.ResolvePlatformCapability(context.Background(), policy, profile)
	if err != nil {
		t.Fatal(err)
	}
	if probe.calls != 0 {
		t.Fatal("first-run probe executed during lazy resolution")
	}
	state, err := source.Capability(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectedRequest := PlatformCapabilityProbeRequest{
		Format: PlatformCapabilityProbeRequestFormat, TargetClusterUID: policy.TargetClusterUID,
		IntentRevision: policy.IntentRevision, PlatformRevision: policy.PlatformRevision,
		ExecutionFixture: profile.ExecutionFixture, ContractDigest: profile.CapabilityContractDigest,
		ExecutableDigest: profile.CapabilityExecutableDigest,
	}
	if probe.calls != 1 || probe.request != expectedRequest {
		t.Fatalf("probe did not receive the exact typed binding: calls=%d request=%#v", probe.calls, probe.request)
	}
	if state.TargetClusterUID != policy.TargetClusterUID || state.IntentRevision != policy.IntentRevision || state.PlatformRevision != policy.PlatformRevision || state.ExecutionFixture != profile.ExecutionFixture || state.ContractDigest != profile.CapabilityContractDigest || state.ExecutableDigest != profile.CapabilityExecutableDigest || !state.Passed {
		t.Fatalf("capability assertion differs from probe binding: %#v", state)
	}
	if err := observation.ValidatePlatformCapabilityState(state); err != nil {
		t.Fatalf("probe result is not canonical capability evidence: %v", err)
	}
	if _, err := source.Capability(context.Background()); err == nil || probe.calls != 1 {
		t.Fatalf("single-use capability source permitted retry: err=%v calls=%d", err, probe.calls)
	}
}

func TestFirstRunPlatformCapabilityResolverFailsClosedAndRedactsProbeErrors(t *testing.T) {
	profile := runnerPlatformProfile()
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: profile.IntentRevision,
		EnablementRevision: digestOf("e"), PlatformRevision: profile.PlatformRevision,
		TargetClusterUID: "cluster-uid-disposable-ok147", Required: []string{"PlatformReady"},
	}
	probe := &recordingPlatformCapabilityProbe{err: errors.New("secret target response")}
	resolver, err := NewFirstRunPlatformCapabilityResolver(probe, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	foreign := policy
	foreign.PlatformRevision = digestOf("9")
	if _, err := resolver.ResolvePlatformCapability(context.Background(), foreign, profile); err == nil || probe.calls != 0 {
		t.Fatalf("foreign policy reached probe: err=%v calls=%d", err, probe.calls)
	}
	source, err := resolver.ResolvePlatformCapability(context.Background(), policy, profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Capability(context.Background()); err == nil || strings.Contains(err.Error(), "secret target") {
		t.Fatalf("probe error was accepted or leaked: %v", err)
	}
	if _, err := source.Capability(context.Background()); err == nil || probe.calls != 1 {
		t.Fatalf("failed probe was retried: err=%v calls=%d", err, probe.calls)
	}
}

func TestPlatformCapabilityProbeRequestHasNoCommandSurface(t *testing.T) {
	typeOfRequest := reflect.TypeOf(PlatformCapabilityProbeRequest{})
	expected := []string{"Format", "TargetClusterUID", "IntentRevision", "PlatformRevision", "ExecutionFixture", "ContractDigest", "ExecutableDigest"}
	if typeOfRequest.NumField() != len(expected) {
		t.Fatalf("probe request gained an unreviewed field: %#v", typeOfRequest)
	}
	for index, name := range expected {
		if typeOfRequest.Field(index).Name != name || typeOfRequest.Field(index).Type.Kind() != reflect.String {
			t.Fatalf("unexpected probe request field %d: %#v", index, typeOfRequest.Field(index))
		}
	}
}

type recordingPlatformCapabilityProbe struct {
	result  PlatformCapabilityProbeResult
	err     error
	request PlatformCapabilityProbeRequest
	calls   int
}

func (probe *recordingPlatformCapabilityProbe) Probe(_ context.Context, request PlatformCapabilityProbeRequest) (PlatformCapabilityProbeResult, error) {
	probe.calls++
	probe.request = request
	return probe.result, probe.err
}
