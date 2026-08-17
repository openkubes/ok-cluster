package runner

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
)

func TestRuntimeBindingStageComposesAndResumesWithoutRebinding(t *testing.T) {
	config := runtimeBindingBundleConfig(t)
	bundle, err := LoadRuntimeBindingStageBundle(config)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := bundle.Decision()
	if err != nil || decision.StageID != "runtime-binding" || decision.Authority != "runner" {
		t.Fatalf("runtime binding decision differs: %#v %v", decision, err)
	}
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	workloadAPI := newRuntimeBindingWorkloadAPI(t, false)
	defer workloadAPI.Close()
	runtime := runtimeBindingStageRuntime(t, bundle, ledgerAPI.Server, workloadAPI.Server, "ledger-token", "workload-token")
	opened, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if ledgerAPI.RequestCount() != 0 || workloadAPI.RequestCount() != 0 {
		t.Fatal("opening runtime binding stage contacted Kubernetes")
	}
	receipt, err := opened.Run(context.Background())
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" || receipt.StageReceiptDigest == "" {
		t.Fatalf("runtime binding stage did not complete: %#v %v", receipt, err)
	}
	evidence, err := opened.EvidenceReceipt()
	if err != nil || evidence.State != "SUCCEEDED" || evidence.Material == nil || evidence.Persistence == nil || evidence.Persistence.State != "WRITTEN_VERIFIED" || evidence.KubernetesPersistence != nil || evidence.KubernetesMutationAllowed || evidence.LifecycleMutationAllowed != nil {
		t.Fatalf("runtime binding evidence differs: %#v %v", evidence, err)
	}
	public, _ := json.Marshal(evidence)
	for _, forbidden := range []string{workloadAPI.URL, "kube-system-runtime-uid", "local-path-runtime-uid", "ledger-token", "workload-token", runtime.OutputPath} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("runtime binding evidence exposed private value %q", forbidden)
		}
	}
	stored, err := os.ReadFile(runtime.OutputPath)
	if err != nil || digest.SHA256(stored) != evidence.Material.PrivateMaterialDigest {
		t.Fatalf("private runtime binding differs: %v", err)
	}
	wantRequests := []string{"GET " + runtimeBindingKubeSystemPath, "GET " + runtimeBindingLocalPathPath}
	if !reflect.DeepEqual(workloadAPI.Requests(), wantRequests) {
		t.Fatalf("workload request boundary differs: %v", workloadAPI.Requests())
	}
	evidence.Material.State = "CHANGED"
	retained, err := opened.EvidenceReceipt()
	if err != nil || retained.Material.State != "VERIFIED" {
		t.Fatal("caller mutated retained runtime binding evidence")
	}
	if _, err := opened.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(workloadAPI.Requests(), wantRequests) {
		t.Fatal("persisted runtime binding stage rebound the workload")
	}
}

func TestRuntimeBindingStageComposesImmutableKubernetesPersistence(t *testing.T) {
	bundle, err := LoadRuntimeBindingStageBundle(runtimeBindingBundleConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	managementAPI := newRuntimeBindingLedgerAPI(t)
	defer managementAPI.Close()
	workloadAPI := newRuntimeBindingWorkloadAPI(t, false)
	defer workloadAPI.Close()
	local := runtimeBindingStageRuntime(t, bundle, managementAPI.Server, workloadAPI.Server, "ledger-token", "workload-token")
	runtime := runtimeBindingStageKubernetesRuntime(t, local, "persistence-token")
	opened, err := bundle.OpenKubernetes(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if managementAPI.RequestCount() != 0 || workloadAPI.RequestCount() != 0 {
		t.Fatal("opening Kubernetes-persisted runtime binding contacted an API")
	}
	receipt, err := opened.Run(context.Background())
	if err != nil || receipt.State != "COMPLETED_SUCCEEDED" {
		t.Fatalf("Kubernetes-persisted runtime binding did not complete: %#v %v", receipt, err)
	}
	evidence, err := opened.EvidenceReceipt()
	if err != nil || evidence.Format != RuntimeBindingStageKubernetesEvidenceFormat || evidence.State != "SUCCEEDED" || evidence.Material == nil || evidence.Persistence != nil || evidence.KubernetesPersistence == nil || evidence.KubernetesPersistence.State != "CREATED_VERIFIED" || !evidence.KubernetesMutationAllowed || evidence.LifecycleMutationAllowed == nil || *evidence.LifecycleMutationAllowed {
		t.Fatalf("Kubernetes persistence evidence differs: %#v %v", evidence, err)
	}
	secretName, err := runtimeBindingSecretName(evidence.PlanDigest)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /api/v1/namespaces/openkubes-execution-system/secrets"}
	if !reflect.DeepEqual(managementAPI.SecretRequests(), want) {
		t.Fatalf("runtime binding Secret requests differ: %v", managementAPI.SecretRequests())
	}
	if _, err := os.Lstat(local.OutputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Kubernetes persistence also created the local binding file")
	}
	public, _ := json.Marshal(evidence)
	for _, forbidden := range []string{managementAPI.URL, workloadAPI.URL, "persistence-token", secretName, local.OutputPath} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("Kubernetes persistence evidence exposed private value %q", forbidden)
		}
	}
}

func TestRuntimeBindingStagePersistsRedactedStop(t *testing.T) {
	bundle, err := LoadRuntimeBindingStageBundle(runtimeBindingBundleConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	workloadAPI := newRuntimeBindingWorkloadAPI(t, true)
	defer workloadAPI.Close()
	runtime := runtimeBindingStageRuntime(t, bundle, ledgerAPI.Server, workloadAPI.Server, "ledger-token", "workload-token")
	opened, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	receipt, runErr := opened.Run(context.Background())
	var resultErr *execution.BindingStageResultError
	if !errors.As(runErr, &resultErr) || receipt.State != "COMPLETED_STOPPED" || receipt.StageReceiptDigest == "" {
		t.Fatalf("runtime source failure was not retained: %#v %v", receipt, runErr)
	}
	evidence, err := opened.EvidenceReceipt()
	if err != nil || evidence.State != "STOPPED" || evidence.FailureCategory != "SOURCE_STOPPED" || evidence.Material != nil || evidence.Persistence != nil {
		t.Fatalf("stopped evidence differs: %#v %v", evidence, err)
	}
	if _, err := os.Lstat(runtime.OutputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source failure created private runtime material")
	}
}

func TestRuntimeBindingStageOpenFailsClosedWithoutContact(t *testing.T) {
	config := runtimeBindingBundleConfig(t)
	bundle, err := LoadRuntimeBindingStageBundle(config)
	if err != nil {
		t.Fatal(err)
	}
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	workloadAPI := newRuntimeBindingWorkloadAPI(t, false)
	defer workloadAPI.Close()
	runtime := runtimeBindingStageRuntime(t, bundle, ledgerAPI.Server, workloadAPI.Server, "shared-token", "shared-token")
	if _, err := bundle.Open(runtime); err == nil {
		t.Fatal("shared ledger and workload credential was accepted")
	}
	if ledgerAPI.RequestCount() != 0 || workloadAPI.RequestCount() != 0 {
		t.Fatal("failed runtime binding open contacted Kubernetes")
	}
	runtime = runtimeBindingStageRuntime(t, bundle, ledgerAPI.Server, workloadAPI.Server, "ledger-token", "workload-token")
	runtime.Ledger.Endpoint = runtime.WorkloadEndpointForTest(t) + "/"
	if _, err := bundle.Open(runtime); err == nil {
		t.Fatal("shared ledger and workload endpoint was accepted")
	}
	if _, err := (VerifiedRuntimeBindingStageBundle{}).Open(runtime); err == nil {
		t.Fatal("unverified runtime binding bundle opened credentials")
	}
	if _, err := (OpenedRuntimeBindingStage{}).Run(context.Background()); err == nil {
		t.Fatal("unopened runtime binding stage could run")
	}
	runtime = runtimeBindingStageRuntime(t, bundle, ledgerAPI.Server, workloadAPI.Server, "ledger-token", "workload-token")
	kubernetes := runtimeBindingStageKubernetesRuntime(t, runtime, "ledger-token")
	if _, err := bundle.OpenKubernetes(kubernetes); err == nil {
		t.Fatal("shared ledger and persistence credential was accepted")
	}
	if ledgerAPI.RequestCount() != 0 || workloadAPI.RequestCount() != 0 {
		t.Fatal("failed Kubernetes persistence open contacted an API")
	}
}

func runtimeBindingStageKubernetesRuntime(t *testing.T, local RuntimeBindingStageRuntimeConfig, token string) RuntimeBindingStageKubernetesRuntimeConfig {
	t.Helper()
	tokenPath := filepath.Join(filepath.Dir(local.OutputPath), "persistence-token")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	return RuntimeBindingStageKubernetesRuntimeConfig{
		Ledger: local.Ledger, Workload: local.Workload,
		Persistence: KubernetesAuthorityConfig{
			Endpoint: local.Ledger.Endpoint, AuthorityIdentity: "ok-mgmt",
			TokenFile: tokenPath, CAFile: local.Ledger.CAFile,
		},
		Clock: local.Clock,
	}
}

func runtimeBindingStageRuntime(t *testing.T, bundle VerifiedRuntimeBindingStageBundle, ledgerServer, workloadServer *httptest.Server, ledgerToken, workloadToken string) RuntimeBindingStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	ledgerCA := writeRuntimeBindingServerCA(t, root, "ledger-ca.crt", ledgerServer)
	workloadCA := writeRuntimeBindingServerCA(t, root, "workload-ca.crt", workloadServer)
	workloadCARaw, err := os.ReadFile(workloadCA)
	if err != nil {
		t.Fatal(err)
	}
	ledgerTokenPath, workloadTokenPath := filepath.Join(root, "ledger-token"), filepath.Join(root, "workload-token")
	for path, raw := range map[string][]byte{ledgerTokenPath: []byte(ledgerToken), workloadTokenPath: []byte(workloadToken)} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lifecycle, _ := bundle.prefix[1].Receipt()
	targetUID := "cluster-runtime-uid-147"
	if digest.SHA256([]byte(targetUID)) != lifecycle.TargetClusterUIDDigest {
		t.Fatal("test runtime target differs from lifecycle receipt")
	}
	binding := WorkloadAuthorityBinding{
		Format: WorkloadAuthorityBindingFormat, IntentRevision: bundle.plan.IntentRevision,
		TargetClusterUID: targetUID, TargetIdentityScheme: "capi-cluster-uid/v1",
		Endpoint: workloadServer.URL, CABundleDigest: digest.SHA256(workloadCARaw),
	}
	bindingPath := filepath.Join(root, "workload-binding.json")
	writePlatformJSON(t, bindingPath, binding)
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeBindingStageRuntimeConfig{
		Ledger:     KubernetesLedgerConfig{Endpoint: ledgerServer.URL, Namespace: "openkubes-execution-system", TokenFile: ledgerTokenPath, CAFile: ledgerCA},
		Workload:   WorkloadAuthorityFileResolverConfig{Path: bindingPath, ExpectedBindingDigest: bindingDigest, TokenFile: workloadTokenPath, CAFile: workloadCA},
		OutputPath: filepath.Join(root, "runtime-binding.json"),
		Clock:      func() time.Time { return time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC) },
	}
}

// WorkloadEndpointForTest reloads only the strict semantic binding used by the
// fixture; it exists to keep the unsafe shared-endpoint case explicit.
func (config RuntimeBindingStageRuntimeConfig) WorkloadEndpointForTest(t *testing.T) string {
	t.Helper()
	binding, err := loadWorkloadAuthorityBinding(config.Workload.Path, config.Workload.ExpectedBindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	return binding.Endpoint
}

func writeRuntimeBindingServerCA(t *testing.T, root, name string, server *httptest.Server) string {
	t.Helper()
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type runtimeBindingWorkloadAPI struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
}

func newRuntimeBindingWorkloadAPI(t *testing.T, fail bool) *runtimeBindingWorkloadAPI {
	t.Helper()
	api := &runtimeBindingWorkloadAPI{}
	api.Server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		api.mu.Lock()
		api.requests = append(api.requests, request.Method+" "+request.URL.RequestURI())
		api.mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer workload-token" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		if fail {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		switch request.URL.Path {
		case runtimeBindingKubeSystemPath:
			fmt.Fprint(response, `{"kind":"Namespace","metadata":{"uid":"kube-system-runtime-uid"}}`)
		case runtimeBindingLocalPathPath:
			fmt.Fprint(response, `{"kind":"StorageClass","metadata":{"uid":"local-path-runtime-uid"},"provisioner":"rancher.io/local-path"}`)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	return api
}

func (api *runtimeBindingWorkloadAPI) Requests() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]string(nil), api.requests...)
}

func (api *runtimeBindingWorkloadAPI) RequestCount() int { return len(api.Requests()) }

type runtimeBindingLedgerAPI struct {
	*httptest.Server
	mu             sync.Mutex
	objects        map[string]map[string]any
	secret         map[string]any
	requests       int
	secretRequests []string
}

func newRuntimeBindingLedgerAPI(t *testing.T) *runtimeBindingLedgerAPI {
	t.Helper()
	api := &runtimeBindingLedgerAPI{objects: map[string]map[string]any{}}
	api.Server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		api.requests++
		response.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") == "Bearer persistence-token" {
			api.secretRequests = append(api.secretRequests, request.Method+" "+request.URL.RequestURI())
			prefix := "/api/v1/namespaces/openkubes-execution-system/secrets"
			if request.Method != http.MethodPost || request.URL.Path != prefix || api.secret != nil {
				response.WriteHeader(http.StatusConflict)
				return
			}
			if err := json.NewDecoder(request.Body).Decode(&api.secret); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			metadata := api.secret["metadata"].(map[string]any)
			metadata["uid"], metadata["resourceVersion"] = "runtime-binding-secret-uid", "1"
			response.WriteHeader(http.StatusCreated)
			json.NewEncoder(response).Encode(api.secret)
			return
		}
		if request.Header.Get("Authorization") != "Bearer ledger-token" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		prefix := "/api/v1/namespaces/openkubes-execution-system/configmaps"
		if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, prefix+"/") {
			name := strings.TrimPrefix(request.URL.Path, prefix+"/")
			object, ok := api.objects[name]
			if !ok {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(response).Encode(object)
			return
		}
		if request.Method == http.MethodPost && request.URL.Path == prefix {
			var object map[string]any
			if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			metadata := object["metadata"].(map[string]any)
			name := metadata["name"].(string)
			if _, exists := api.objects[name]; exists {
				response.WriteHeader(http.StatusConflict)
				return
			}
			metadata["uid"], metadata["resourceVersion"] = "ledger-runtime-uid", "1"
			api.objects[name] = object
			response.WriteHeader(http.StatusCreated)
			json.NewEncoder(response).Encode(object)
			return
		}
		response.WriteHeader(http.StatusMethodNotAllowed)
	}))
	return api
}

func (api *runtimeBindingLedgerAPI) RequestCount() int {
	api.mu.Lock()
	defer api.mu.Unlock()
	return api.requests
}

func (api *runtimeBindingLedgerAPI) SecretRequests() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]string(nil), api.secretRequests...)
}
