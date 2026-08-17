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
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func TestPlatformObservationStageRunsOnceAndReplaysDurableReceipt(t *testing.T) {
	fixture := platformObservationBundleFixture(t)
	bundle, err := LoadPlatformObservationStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 17, 21, 0, 0, 0, time.UTC)
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	argoAPI := newPlatformObservationExecutionAPI(t, bundle)
	defer argoAPI.Close()
	runtime := platformObservationExecutionRuntime(t, bundle, ledgerAPI.Server, argoAPI.Server, at)
	opened, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if ledgerAPI.RequestCount() != 0 || argoAPI.RequestCount() != 0 {
		t.Fatal("opening platform observation stage contacted Kubernetes")
	}
	receipt, err := opened.Run(context.Background())
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageID != "platform-observation" || receipt.StageReceiptDigest == "" {
		t.Fatalf("platform observation stage did not complete: %#v %v", receipt, err)
	}
	want := make([]string, len(bundle.profile.RequiredApplications))
	for index, application := range bundle.profile.RequiredApplications {
		want[index] = "/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/" + application.Name
	}
	if !reflect.DeepEqual(argoAPI.Requests(), want) || runtime.Capability.(*platformObservationCapabilitySource).calls != 1 {
		t.Fatalf("platform observation request boundary differs: got=%v capability=%d", argoAPI.Requests(), runtime.Capability.(*platformObservationCapabilitySource).calls)
	}
	replayed, err := opened.Run(context.Background())
	if err != nil || replayed.StageReceiptDigest != receipt.StageReceiptDigest || !reflect.DeepEqual(argoAPI.Requests(), want) || runtime.Capability.(*platformObservationCapabilitySource).calls != 1 {
		t.Fatalf("durable platform observation receipt replayed sources: %#v %v", replayed, err)
	}
}

func platformObservationExecutionRuntime(t *testing.T, bundle VerifiedPlatformObservationStageBundle, ledgerServer, argoServer *httptest.Server, at time.Time) PlatformObservationStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	ledgerCA := writeRuntimeBindingServerCA(t, root, "ledger-ca.crt", ledgerServer)
	argoCA := writeRuntimeBindingServerCA(t, root, "argo-ca.crt", argoServer)
	argoCABytes, err := os.ReadFile(argoCA)
	if err != nil {
		t.Fatal(err)
	}
	capability := observation.PlatformCapabilityState{
		Format: observation.PlatformCapabilityFormat, ObservedAt: at.Format(time.RFC3339Nano),
		TargetClusterUID: targetAccessRuntimeUID, IntentRevision: bundle.plan.IntentRevision,
		PlatformRevision: bundle.plan.PlatformRevision, ExecutionFixture: bundle.plan.ExecutionFixture,
		ContractDigest: bundle.profile.CapabilityContractDigest, ExecutableDigest: bundle.profile.CapabilityExecutableDigest, Passed: true,
	}
	capability.EvidenceDigest, err = observation.PlatformCapabilityDigest(capability)
	if err != nil {
		t.Fatal(err)
	}
	current := at
	return PlatformObservationStageRuntimeConfig{
		Ledger: KubernetesLedgerConfig{Endpoint: ledgerServer.URL, Namespace: "openkubes-execution-system", TokenFile: writeBundleFile(t, root, "ledger-token", []byte("ledger-token")), CAFile: ledgerCA},
		Argo: KubernetesAuthorityConfig{
			Endpoint: argoServer.URL, AuthorityIdentity: bundle.plan.Authorities.GitOps,
			TokenFile: writeBundleFile(t, root, "argo-token", []byte("argo-reader-token")), CAFile: argoCA,
			CABundleDigest: digest.SHA256(argoCABytes),
		},
		Runtime: platformObservationRuntimeMaterial(t, bundle), Capability: &platformObservationCapabilitySource{capability: capability},
		PollInterval: time.Second, PollTimeout: time.Minute, Clock: func() time.Time { return current },
		Wait: func(_ context.Context, duration time.Duration) error { current = current.Add(duration); return nil },
	}
}

type platformObservationCapabilitySource struct {
	capability observation.PlatformCapabilityState
	calls      int
}

func (source *platformObservationCapabilitySource) Capability(context.Context) (observation.PlatformCapabilityState, error) {
	source.calls++
	return source.capability, nil
}

type platformObservationExecutionAPI struct {
	*httptest.Server
	mu       sync.Mutex
	objects  map[string]map[string]any
	requests []string
}

func newPlatformObservationExecutionAPI(t *testing.T, bundle VerifiedPlatformObservationStageBundle) *platformObservationExecutionAPI {
	t.Helper()
	expected := stageplan.Expected{
		ContractIdentity: bundle.plan.ContractIdentity, IntentRevision: bundle.plan.IntentRevision,
		EnablementRevision: bundle.plan.EnablementRevision, PlatformRevision: bundle.plan.PlatformRevision,
		ExecutionFixture: bundle.plan.ExecutionFixture, InfrastructureAuthority: bundle.plan.Authorities.Infrastructure,
		ManagementAuthority: bundle.plan.Authorities.Management, GitOpsAuthority: bundle.plan.Authorities.GitOps,
	}
	raw, _ := runnerPlatformApplications(t, expected)
	objects := map[string]map[string]any{}
	for index, document := range strings.Split(string(raw), "\n---\n") {
		var object map[string]any
		if err := json.Unmarshal([]byte(document), &object); err != nil {
			t.Fatal(err)
		}
		metadata := object["metadata"].(map[string]any)
		metadata["uid"] = "platform-observation-application-uid-" + string(rune('a'+index))
		metadata["resourceVersion"] = "1"
		object["status"] = map[string]any{
			"sync":   map[string]any{"revision": strings.Repeat("6", 40), "status": "Synced"},
			"health": map[string]any{"status": "Healthy"},
		}
		name := metadata["name"].(string)
		objects["/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/"+name] = object
	}
	api := &platformObservationExecutionAPI{objects: objects}
	api.Server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		api.requests = append(api.requests, request.URL.Path)
		response.Header().Set("Content-Type", "application/json")
		if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer argo-reader-token" {
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

func (api *platformObservationExecutionAPI) Requests() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]string(nil), api.requests...)
}

func (api *platformObservationExecutionAPI) RequestCount() int { return len(api.Requests()) }
