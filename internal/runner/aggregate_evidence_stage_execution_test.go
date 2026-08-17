package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestAggregateEvidenceStageRunsAllAuthoritiesOnceAndReplaysDurably(t *testing.T) {
	config := aggregateEvidenceBundleFixture(t)
	bundle, err := LoadAggregateEvidenceStageBundle(config)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 17, 23, 0, 0, 0, time.UTC)
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	managementAPI := newAggregateCAPIExecutionAPI(t, bundle)
	defer managementAPI.Close()
	_, platformProfile := runnerPlatformApplications(t, bundleExpected(bundle))
	argoAPI := newAggregateArgoExecutionAPI(t, bundle, platformProfile)
	defer argoAPI.Close()
	network := &aggregateExecutionNetworkSource{}
	capability := &platformObservationCapabilitySource{capability: aggregateCapabilityState(t, bundle, platformProfile, at)}

	runtime := aggregateEvidenceExecutionRuntime(t, bundle, ledgerAPI.Server, managementAPI.Server, argoAPI.Server, platformProfile, capability, network, at)
	opened, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if ledgerAPI.RequestCount() != 0 || managementAPI.RequestCount() != 0 || argoAPI.RequestCount() != 0 || network.Calls() != 0 || capability.calls != 0 {
		t.Fatal("opening aggregate evidence stage contacted an authority source")
	}
	receipt, err := opened.Run(context.Background())
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageID != "aggregate-evidence" || receipt.StageReceiptDigest == "" {
		t.Fatalf("aggregate evidence stage did not complete: %#v %v", receipt, err)
	}
	wantArgo := make([]string, len(platformProfile.RequiredApplications))
	for index, application := range platformProfile.RequiredApplications {
		wantArgo[index] = "/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/" + application.Name
	}
	if managementAPI.RequestCount() != 1 || !reflect.DeepEqual(argoAPI.Requests(), wantArgo) || network.Calls() != 1 || capability.calls != 1 {
		t.Fatalf("aggregate source boundary differs: capi=%d argo=%v network=%d capability=%d", managementAPI.RequestCount(), argoAPI.Requests(), network.Calls(), capability.calls)
	}
	replayed, err := opened.Run(context.Background())
	if err != nil || replayed.StageReceiptDigest != receipt.StageReceiptDigest || managementAPI.RequestCount() != 1 || !reflect.DeepEqual(argoAPI.Requests(), wantArgo) || network.Calls() != 1 || capability.calls != 1 {
		t.Fatalf("durable aggregate receipt replayed sources: %#v capi=%d argo=%v network=%d capability=%d err=%v", replayed, managementAPI.RequestCount(), argoAPI.Requests(), network.Calls(), capability.calls, err)
	}
}

func aggregateEvidenceExecutionRuntime(t *testing.T, bundle VerifiedAggregateEvidenceStageBundle, ledgerServer, managementServer, argoServer *httptest.Server, platformProfile observation.PlatformProfile, capability observation.PlatformCapabilitySource, network *aggregateExecutionNetworkSource, at time.Time) AggregateEvidenceStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	ledgerCA := writeRuntimeBindingServerCA(t, root, "ledger-ca.crt", ledgerServer)
	managementCA := writeRuntimeBindingServerCA(t, root, "management-ca.crt", managementServer)
	argoCA := writeRuntimeBindingServerCA(t, root, "argo-ca.crt", argoServer)
	argoCABytes, err := os.ReadFile(argoCA)
	if err != nil {
		t.Fatal(err)
	}
	runtime := AggregateEvidenceStageRuntimeConfig{
		Ledger: KubernetesLedgerConfig{Endpoint: ledgerServer.URL, Namespace: "openkubes-execution-system", TokenFile: writeBundleFile(t, root, "ledger-token", []byte("ledger-token")), CAFile: ledgerCA},
		Observer: KubernetesAggregateObserverConfig{
			Management:                  KubernetesAuthorityConfig{Endpoint: managementServer.URL, AuthorityIdentity: bundle.plan.Authorities.Management, TokenFile: writeBundleFile(t, root, "management-token", []byte("management-token")), CAFile: managementCA},
			ExpectedManagementAuthority: bundle.plan.Authorities.Management,
			Argo:                        KubernetesAuthorityConfig{Endpoint: argoServer.URL, AuthorityIdentity: bundle.plan.Authorities.GitOps, TokenFile: writeBundleFile(t, root, "argo-token", []byte("argo-token")), CAFile: argoCA, CABundleDigest: digest.SHA256(argoCABytes)},
			ExpectedArgoAuthority:       bundle.plan.Authorities.GitOps,
			Namespace:                   bundle.plan.ContractIdentity.Namespace, Name: bundle.plan.ContractIdentity.Name, HCPName: bundle.plan.ContractIdentity.Name + "-cilium",
			NetworkProfile: runnerAggregateNetworkProfile(bundleExpected(bundle)), PlatformProfile: platformProfile,
			WorkloadAuthority: WorkloadAuthorityResolverFunc(func(_ context.Context, policy observation.Policy) (KubernetesAuthorityConfig, error) {
				return KubernetesAuthorityConfig{AuthorityIdentity: policy.TargetClusterUID}, nil
			}),
			PlatformCapability: PlatformCapabilityResolverFunc(func(context.Context, observation.Policy, observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
				return capability, nil
			}),
			Clock: func() time.Time { return at },
		},
		Runtime: aggregateRuntimeBindingMaterial(t, bundle),
	}
	runtime.openObserver = func(config KubernetesAggregateObserverConfig) (*KubernetesAggregateObserver, error) {
		observer, err := OpenKubernetesAggregateObserver(config)
		if err != nil {
			return nil, err
		}
		observer.openers.network = func(KubernetesNetworkObserverConfig) (observation.NetworkEvidenceSource, error) { return network, nil }
		return observer, nil
	}
	return runtime
}

type aggregateExecutionNetworkSource struct {
	mu    sync.Mutex
	calls int
}

func (source *aggregateExecutionNetworkSource) Observe(_ context.Context, policy observation.Policy, _ observation.NetworkProfile) (observation.Evidence, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	return aggregateRunnerEvidence(policy, "NetworkReady"), nil
}

func (source *aggregateExecutionNetworkSource) Calls() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.calls
}

type aggregateCAPIExecutionAPI struct {
	*httptest.Server
	mu       sync.Mutex
	requests int
}

func newAggregateCAPIExecutionAPI(t *testing.T, bundle VerifiedAggregateEvidenceStageBundle) *aggregateCAPIExecutionAPI {
	t.Helper()
	api := &aggregateCAPIExecutionAPI{}
	path := "/apis/cluster.x-k8s.io/v1beta2/namespaces/" + bundle.plan.ContractIdentity.Namespace + "/clusters/" + bundle.plan.ContractIdentity.Name
	object := map[string]any{
		"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster",
		"metadata": map[string]any{
			"name": bundle.plan.ContractIdentity.Name, "namespace": bundle.plan.ContractIdentity.Namespace,
			"uid": targetAccessRuntimeUID, "resourceVersion": "41", "generation": 7,
			"annotations": map[string]string{"openkubes.io/intent-revision": bundle.plan.IntentRevision},
		},
		"status": map[string]any{"conditions": []map[string]any{
			{"type": "InfrastructureReady", "status": "True", "reason": "InfrastructureReady", "observedGeneration": 7},
			{"type": "ControlPlaneAvailable", "status": "True", "reason": "ControlPlaneAvailable", "observedGeneration": 7},
		}},
	}
	api.Server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		api.mu.Lock()
		api.requests++
		api.mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		if request.Method != http.MethodGet || request.URL.Path != path || request.Header.Get("Authorization") != "Bearer management-token" {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		json.NewEncoder(response).Encode(object)
	}))
	return api
}

func (api *aggregateCAPIExecutionAPI) RequestCount() int {
	api.mu.Lock()
	defer api.mu.Unlock()
	return api.requests
}

type aggregateArgoExecutionAPI struct {
	*httptest.Server
	mu       sync.Mutex
	objects  map[string]map[string]any
	requests []string
}

func newAggregateArgoExecutionAPI(t *testing.T, bundle VerifiedAggregateEvidenceStageBundle, profile observation.PlatformProfile) *aggregateArgoExecutionAPI {
	t.Helper()
	raw, _ := runnerPlatformApplications(t, bundleExpected(bundle))
	objects := map[string]map[string]any{}
	for index, document := range strings.Split(string(raw), "\n---\n") {
		var object map[string]any
		if err := json.Unmarshal([]byte(document), &object); err != nil {
			t.Fatal(err)
		}
		metadata := object["metadata"].(map[string]any)
		metadata["uid"] = "aggregate-application-uid-" + string(rune('a'+index))
		metadata["resourceVersion"] = "1"
		object["status"] = map[string]any{"sync": map[string]any{"revision": strings.Repeat("6", 40), "status": "Synced"}, "health": map[string]any{"status": "Healthy"}}
		name := metadata["name"].(string)
		objects["/apis/argoproj.io/v1alpha1/namespaces/"+profile.ArgoNamespace+"/applications/"+name] = object
	}
	api := &aggregateArgoExecutionAPI{objects: objects}
	api.Server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		api.requests = append(api.requests, request.URL.Path)
		response.Header().Set("Content-Type", "application/json")
		if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer argo-token" {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		object, exists := api.objects[request.URL.Path]
		if !exists {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(response).Encode(object)
	}))
	return api
}

func (api *aggregateArgoExecutionAPI) Requests() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]string(nil), api.requests...)
}

func (api *aggregateArgoExecutionAPI) RequestCount() int { return len(api.Requests()) }

func aggregateCapabilityState(t *testing.T, bundle VerifiedAggregateEvidenceStageBundle, profile observation.PlatformProfile, at time.Time) observation.PlatformCapabilityState {
	t.Helper()
	state := observation.PlatformCapabilityState{
		Format: observation.PlatformCapabilityFormat, ObservedAt: at.Format(time.RFC3339Nano), TargetClusterUID: targetAccessRuntimeUID,
		IntentRevision: bundle.plan.IntentRevision, PlatformRevision: bundle.plan.PlatformRevision, ExecutionFixture: bundle.plan.ExecutionFixture,
		ContractDigest: profile.CapabilityContractDigest, ExecutableDigest: profile.CapabilityExecutableDigest, Passed: true,
	}
	var err error
	state.EvidenceDigest, err = observation.PlatformCapabilityDigest(state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
