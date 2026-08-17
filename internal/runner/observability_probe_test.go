package runner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestObservabilityCapabilityProbeRunsFixedSequenceAndCleanup(t *testing.T) {
	request := observabilityProbeRequest()
	transport := &recordingObservabilityTransport{}
	probe, err := NewObservabilityCapabilityProbe(transport, ObservabilityCapabilityProbeConfig{
		Namespace: "ok-observability", ExpectedContractDigest: request.ContractDigest,
		ExpectedExecutableDigest: request.ExecutableDigest, Timeout: 5 * time.Minute, CleanupTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.Probe(context.Background(), request)
	if err != nil || !result.Passed {
		t.Fatalf("fixed observability probe failed: %#v %v", result, err)
	}
	expected := []string{"prepare", "metrics", "dashboards", "logs", "alert-delivery", "autonomy", "cleanup"}
	if !reflect.DeepEqual(transport.calls, expected) {
		t.Fatalf("unexpected capability sequence: %v", transport.calls)
	}
	if transport.run.Format != ObservabilityCapabilityRunFormat || !strings.HasPrefix(transport.run.RunID, "ok147-") || len(transport.run.RunID) != 30 || transport.run.Namespace != "ok-observability" || transport.run.TargetClusterUID != request.TargetClusterUID || transport.run.ContractDigest != request.ContractDigest || transport.run.ExecutableDigest != request.ExecutableDigest {
		t.Fatalf("capability run is not deterministically bound: %#v", transport.run)
	}
	second, _ := observabilityCapabilityRun(request, "ok-observability")
	if second != transport.run {
		t.Fatal("equivalent capability request produced another run identity")
	}
}

func TestObservabilityCapabilityProbeFailsClosedAndAlwaysCleansPartialState(t *testing.T) {
	request := observabilityProbeRequest()
	for name, configure := range map[string]func(*recordingObservabilityTransport){
		"prepare error":   func(transport *recordingObservabilityTransport) { transport.failAt = "prepare" },
		"false guarantee": func(transport *recordingObservabilityTransport) { transport.falseAt = "logs" },
		"check error":     func(transport *recordingObservabilityTransport) { transport.failAt = "dashboards" },
		"cleanup error":   func(transport *recordingObservabilityTransport) { transport.failAt = "cleanup" },
	} {
		t.Run(name, func(t *testing.T) {
			transport := &recordingObservabilityTransport{}
			configure(transport)
			probe, err := NewObservabilityCapabilityProbe(transport, ObservabilityCapabilityProbeConfig{
				Namespace: "ok-observability", ExpectedContractDigest: request.ContractDigest,
				ExpectedExecutableDigest: request.ExecutableDigest, Timeout: time.Minute, CleanupTimeout: 10 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := probe.Probe(context.Background(), request)
			if transport.calls[len(transport.calls)-1] != "cleanup" {
				t.Fatalf("synthetic cleanup was not last: %v", transport.calls)
			}
			if name == "false guarantee" {
				if err != nil || result.Passed {
					t.Fatalf("false guarantee was not represented as a capability failure: %#v %v", result, err)
				}
			} else if err == nil || result.Passed || strings.Contains(err.Error(), "transport secret") {
				t.Fatalf("operational failure was accepted or leaked: %#v %v", result, err)
			}
		})
	}
}

func TestObservabilityCapabilityProbeRejectsForeignContractBeforeTransport(t *testing.T) {
	request := observabilityProbeRequest()
	transport := &recordingObservabilityTransport{}
	probe, err := NewObservabilityCapabilityProbe(transport, ObservabilityCapabilityProbeConfig{
		Namespace: "ok-observability", ExpectedContractDigest: request.ContractDigest,
		ExpectedExecutableDigest: request.ExecutableDigest, Timeout: time.Minute, CleanupTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	request.ExecutableDigest = digestOf("9")
	if _, err := probe.Probe(context.Background(), request); err == nil || len(transport.calls) != 0 {
		t.Fatalf("foreign executable reached capability transport: err=%v calls=%v", err, transport.calls)
	}
}

func TestObservabilityCapabilityTransportHasOnlyContractOperations(t *testing.T) {
	typeOfTransport := reflect.TypeOf((*ObservabilityCapabilityTransport)(nil)).Elem()
	expected := []string{"CleanupSyntheticResources", "PrepareSyntheticMetrics", "VerifyAlertDelivery", "VerifyAutonomy", "VerifyDashboards", "VerifyLogs", "VerifyMetrics"}
	if typeOfTransport.NumMethod() != len(expected) {
		t.Fatalf("capability transport gained an unreviewed operation: %#v", typeOfTransport)
	}
	for index, name := range expected {
		if typeOfTransport.Method(index).Name != name {
			t.Fatalf("unexpected capability transport operation %d: %s", index, typeOfTransport.Method(index).Name)
		}
	}
}

func observabilityProbeRequest() PlatformCapabilityProbeRequest {
	return PlatformCapabilityProbeRequest{
		Format: PlatformCapabilityProbeRequestFormat, TargetClusterUID: "cluster-uid-disposable-ok147",
		IntentRevision: digestOf("a"), PlatformRevision: digestOf("b"), ExecutionFixture: digestOf("c"),
		ContractDigest: digestOf("4"), ExecutableDigest: digestOf("5"),
	}
}

type recordingObservabilityTransport struct {
	calls   []string
	run     ObservabilityCapabilityRun
	failAt  string
	falseAt string
}

func (transport *recordingObservabilityTransport) record(name string, run ObservabilityCapabilityRun) (bool, error) {
	transport.calls = append(transport.calls, name)
	transport.run = run
	if transport.failAt == name {
		return false, errors.New("transport secret detail")
	}
	return transport.falseAt != name, nil
}

func (transport *recordingObservabilityTransport) PrepareSyntheticMetrics(_ context.Context, run ObservabilityCapabilityRun) error {
	_, err := transport.record("prepare", run)
	return err
}
func (transport *recordingObservabilityTransport) VerifyMetrics(_ context.Context, run ObservabilityCapabilityRun) (bool, error) {
	return transport.record("metrics", run)
}
func (transport *recordingObservabilityTransport) VerifyDashboards(_ context.Context, run ObservabilityCapabilityRun) (bool, error) {
	return transport.record("dashboards", run)
}
func (transport *recordingObservabilityTransport) VerifyLogs(_ context.Context, run ObservabilityCapabilityRun) (bool, error) {
	return transport.record("logs", run)
}
func (transport *recordingObservabilityTransport) VerifyAlertDelivery(_ context.Context, run ObservabilityCapabilityRun) (bool, error) {
	return transport.record("alert-delivery", run)
}
func (transport *recordingObservabilityTransport) VerifyAutonomy(_ context.Context, run ObservabilityCapabilityRun) (bool, error) {
	return transport.record("autonomy", run)
}
func (transport *recordingObservabilityTransport) CleanupSyntheticResources(_ context.Context, run ObservabilityCapabilityRun) error {
	_, err := transport.record("cleanup", run)
	return err
}
