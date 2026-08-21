package runner

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestKubernetesObservabilityTransportOwnsCreateChecksAndCleanup(t *testing.T) {
	api := newCapabilityFixtureAPI(t)
	client := newCapabilityFixtureClient(t, api.client())
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	checks := &recordingCapabilityChecks{}
	transport, err := newKubernetesObservabilityTransport(client, run, checks)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := NewObservabilityCapabilityProbe(transport, ObservabilityCapabilityProbeConfig{
		Namespace: run.Namespace, ExpectedContractDigest: run.ContractDigest, ExpectedExecutableDigest: run.ExecutableDigest,
		Timeout: time.Minute, CleanupTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.Probe(context.Background(), observabilityProbeRequest())
	if err != nil || !result.Passed {
		t.Fatalf("composed Kubernetes transport failed: %#v %v", result, err)
	}
	expected := []string{"metrics", "dashboards", "logs", "alert-delivery", "autonomy"}
	if !reflect.DeepEqual(checks.calls, expected) || len(api.objects) != 0 {
		t.Fatalf("fixed checks or owned cleanup differ: checks=%v remaining=%d", checks.calls, len(api.objects))
	}
	for _, fixture := range checks.fixtures {
		if fixture.FixtureDigest != client.FixtureDigest() || fixture.RunID != run.RunID {
			t.Fatalf("check received foreign fixture: %#v", fixture)
		}
	}
}

func TestKubernetesObservabilityTransportCleansKnownPartialPrefix(t *testing.T) {
	api := newCapabilityFixtureAPI(t)
	api.failPost = 3
	client := newCapabilityFixtureClient(t, api.client())
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	transport, err := newKubernetesObservabilityTransport(client, run, &recordingCapabilityChecks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.PrepareSyntheticMetrics(context.Background(), run); err == nil {
		t.Fatal("partial fixture creation was accepted")
	}
	if len(api.objects) != 2 {
		t.Fatalf("fake partial prefix differs: %d", len(api.objects))
	}
	if err := transport.CleanupSyntheticResources(context.Background(), run); err != nil || len(api.objects) != 0 {
		t.Fatalf("known partial prefix was not safely cleaned: remaining=%d err=%v", len(api.objects), err)
	}
}

func TestKubernetesObservabilityTransportRejectsOutOfOrderCheck(t *testing.T) {
	api := newCapabilityFixtureAPI(t)
	client := newCapabilityFixtureClient(t, api.client())
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	checks := &recordingCapabilityChecks{}
	transport, err := newKubernetesObservabilityTransport(client, run, checks)
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.PrepareSyntheticMetrics(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.VerifyLogs(context.Background(), run); err == nil || len(checks.calls) != 0 {
		t.Fatalf("out-of-order check reached adapter: err=%v calls=%v", err, checks.calls)
	}
	if err := transport.CleanupSyntheticResources(context.Background(), run); err != nil {
		t.Fatal(err)
	}
}

func TestKubernetesObservabilityTransportRejectsUnknownPartialState(t *testing.T) {
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	calls := 0
	httpClient := &http.Client{Transport: capabilityRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method == http.MethodGet {
			return capabilityJSONResponse(http.StatusNotFound, map[string]any{"reason": "NotFound"}, nil), nil
		}
		return nil, errors.New("secret transport failure")
	})}
	client := newCapabilityFixtureClient(t, httpClient)
	transport, err := newKubernetesObservabilityTransport(client, run, &recordingCapabilityChecks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.PrepareSyntheticMetrics(context.Background(), run); err == nil || calls != 5 {
		t.Fatalf("unknown POST outcome was accepted: calls=%d err=%v", calls, err)
	}
	if err := transport.CleanupSyntheticResources(context.Background(), run); err == nil || strings.Contains(err.Error(), "secret transport") {
		t.Fatalf("unknown partial state was cleaned or leaked: %v", err)
	}
}

func TestOpenKubernetesObservabilityTransportBindsCredentialAndCA(t *testing.T) {
	root := t.TempDir()
	tokenPath, caPath := filepath.Join(root, "token"), filepath.Join(root, "ca.crt")
	ca := testCA(t)
	if err := os.WriteFile(tokenPath, []byte("short-lived-workload-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	config := KubernetesObservabilityTransportConfig{
		Workload: KubernetesAuthorityConfig{
			Endpoint: "https://192.168.100.213:6443", AuthorityIdentity: run.TargetClusterUID,
			TokenFile: tokenPath, CAFile: caPath, CABundleDigest: digest.SHA256(ca),
		},
		Run: run, Fixture: capabilityFixtureConfig(), Checks: &recordingCapabilityChecks{},
	}
	if _, err := OpenKubernetesObservabilityTransport(config); err != nil {
		t.Fatal(err)
	}
	config.Workload.CABundleDigest = digestOf("9")
	if _, err := OpenKubernetesObservabilityTransport(config); err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("foreign CA accepted or path leaked: %v", err)
	}
}

func TestOpenKubernetesObservabilityTransportAcceptsLifecycleClientCertificate(t *testing.T) {
	root := t.TempDir()
	ca, certificate, key := testClientCredential(t)
	caPath := filepath.Join(root, "workload-ca.crt")
	kubeconfigPath := filepath.Join(root, "workload.kubeconfig")
	endpoint := "https://192.0.2.90:6443"
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kubeconfigPath, testClientKubeconfig(endpoint, ca, certificate, key), 0o600); err != nil {
		t.Fatal(err)
	}
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	transport, err := OpenKubernetesObservabilityTransport(KubernetesObservabilityTransportConfig{
		Workload: KubernetesAuthorityConfig{
			Endpoint: endpoint, AuthorityIdentity: run.TargetClusterUID, KubeconfigFile: kubeconfigPath,
			CAFile: caPath, CABundleDigest: digest.SHA256(ca),
		},
		Run: run, Fixture: capabilityFixtureConfig(), Checks: &recordingCapabilityChecks{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if transport.client == nil || !transport.client.clientCertificate || transport.client.token != "" {
		t.Fatalf("lifecycle client-certificate authority was not retained: %#v", transport.client)
	}
}

type recordingCapabilityChecks struct {
	calls    []string
	fixtures []ObservabilitySyntheticFixture
}

func (checks *recordingCapabilityChecks) record(name string, fixture ObservabilitySyntheticFixture) (bool, error) {
	checks.calls = append(checks.calls, name)
	checks.fixtures = append(checks.fixtures, fixture)
	return true, nil
}

func (checks *recordingCapabilityChecks) Metrics(_ context.Context, _ ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (bool, error) {
	return checks.record("metrics", fixture)
}
func (checks *recordingCapabilityChecks) Dashboards(_ context.Context, _ ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (bool, error) {
	return checks.record("dashboards", fixture)
}
func (checks *recordingCapabilityChecks) Logs(_ context.Context, _ ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (bool, error) {
	return checks.record("logs", fixture)
}
func (checks *recordingCapabilityChecks) AlertDelivery(_ context.Context, _ ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (bool, error) {
	return checks.record("alert-delivery", fixture)
}
func (checks *recordingCapabilityChecks) Autonomy(_ context.Context, _ ObservabilityCapabilityRun, fixture ObservabilitySyntheticFixture) (bool, error) {
	return checks.record("autonomy", fixture)
}
