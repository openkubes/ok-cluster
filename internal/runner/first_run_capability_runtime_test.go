package runner

import (
	"context"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestSharedPlatformCapabilityResolverExecutesOnceAcrossStageElevenAndTwelve(t *testing.T) {
	profile := runnerPlatformProfile()
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: profile.IntentRevision,
		EnablementRevision: digestOf("e"), PlatformRevision: profile.PlatformRevision,
		TargetClusterUID: "cluster-uid-disposable-ok147", Required: []string{"PlatformReady"},
	}
	probe := &recordingPlatformCapabilityProbe{result: PlatformCapabilityProbeResult{Passed: true}}
	firstRun, err := NewFirstRunPlatformCapabilityResolver(probe, func() time.Time {
		return time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	shared, err := newSharedPlatformCapabilityResolver(firstRun)
	if err != nil {
		t.Fatal(err)
	}
	stageEleven, err := shared.ResolvePlatformCapability(context.Background(), policy, profile)
	if err != nil {
		t.Fatal(err)
	}
	first, err := stageEleven.Capability(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stageTwelve, err := shared.ResolvePlatformCapability(context.Background(), policy, profile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := stageTwelve.Capability(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != second || probe.calls != 1 {
		t.Fatalf("first-run capability was not reused exactly: first=%#v second=%#v calls=%d", first, second, probe.calls)
	}
	foreign := policy
	foreign.TargetClusterUID = "cluster-uid-foreign"
	if _, err := shared.ResolvePlatformCapability(context.Background(), foreign, profile); err == nil || probe.calls != 1 {
		t.Fatalf("shared capability accepted foreign target: err=%v calls=%d", err, probe.calls)
	}
}

func TestSharedPlatformCapabilityResolverCachesFailureWithoutRetry(t *testing.T) {
	profile := runnerPlatformProfile()
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: profile.IntentRevision,
		EnablementRevision: digestOf("e"), PlatformRevision: profile.PlatformRevision,
		TargetClusterUID: "cluster-uid-disposable-ok147", Required: []string{"PlatformReady"},
	}
	probe := &recordingPlatformCapabilityProbe{err: context.DeadlineExceeded}
	firstRun, _ := NewFirstRunPlatformCapabilityResolver(probe, time.Now)
	shared, _ := newSharedPlatformCapabilityResolver(firstRun)
	source, err := shared.ResolvePlatformCapability(context.Background(), policy, profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Capability(context.Background()); err == nil {
		t.Fatal("failed first-run capability was accepted")
	}
	if _, err := source.Capability(context.Background()); err == nil || probe.calls != 1 {
		t.Fatalf("failed first-run capability was retried: err=%v calls=%d", err, probe.calls)
	}
}
