package stageauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanRuntimeInstallationBindsExactSixObjectOrder(t *testing.T) {
	packaged := runtimeLauncherPackage(t)
	plan, err := PlanRuntimeInstallation(packaged, "ok-mgmt")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Format != RuntimeInstallationPlanFormat || plan.State != "VERIFIED" || plan.Authority != "ok-mgmt" || plan.MutationAllowed || len(plan.Creates) != 6 {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	for index, kind := range []string{"Secret", "ServiceAccount", "PersistentVolumeClaim", "Service", "NetworkPolicy", "StatefulSet"} {
		create := plan.Creates[index]
		if create.Order != index+1 || create.Kind != kind || create.Namespace != "openkubes-execution-system" ||
			create.PreflightMethod != http.MethodGet || create.CreateMethod != http.MethodPost || create.ObjectPath == "" || create.CollectionPath == "" || !digestPattern.MatchString(create.ObjectDigest) {
			t.Fatalf("create %d differs: %#v", index, create)
		}
	}
	if _, err := PlanRuntimeInstallation(packaged, "ok-shared"); err == nil {
		t.Fatal("runtime package accepted a non-management authority")
	}
	public, _ := json.Marshal(plan)
	for _, forbidden := range []string{"token", "authority.key", "tls.key", "secretobjectdigest", "10.43.250.147"} {
		if strings.Contains(strings.ToLower(string(public)), forbidden) {
			t.Fatalf("plan disclosed %q", forbidden)
		}
	}
}

func TestLoadRuntimePackageRequiresPrivateExactPackage(t *testing.T) {
	packaged := runtimeLauncherPackage(t)
	raw, _ := packaged.PrivateBytes()
	receipt, _ := packaged.Receipt()
	receiptRaw, _ := json.Marshal(receipt)
	root := t.TempDir()
	packagePath := filepath.Join(root, "runtime.yaml")
	receiptPath := filepath.Join(root, "receipt.json")
	if err := os.WriteFile(packagePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, receiptRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRuntimePackage(RuntimePackageFileConfig{PackagePath: packagePath, ReceiptPath: receiptPath, ExpectedReceiptDigest: digest.SHA256(receiptRaw)})
	if err != nil {
		t.Fatal(err)
	}
	loadedReceipt, _ := loaded.Receipt()
	if loadedReceipt.PackageDigest != receipt.PackageDigest {
		t.Fatal("loaded package differs")
	}
	if err := os.Chmod(packagePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuntimePackage(RuntimePackageFileConfig{PackagePath: packagePath, ReceiptPath: receiptPath, ExpectedReceiptDigest: digest.SHA256(receiptRaw)}); err == nil {
		t.Fatal("publicly readable private package was accepted")
	}
}

func TestRuntimeLauncherPreflightsAllThenCreatesInOrder(t *testing.T) {
	packaged := runtimeLauncherPackage(t)
	api := newRuntimeInstallerAPI(t)
	launcher := newRuntimeLauncher(t, packaged, api)
	receipt, err := launcher.Launch(context.Background())
	if err != nil || receipt.State != "INSTALLED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 6 {
		t.Fatalf("launch failed: %#v %v", receipt, err)
	}
	plan, _ := PlanRuntimeInstallation(packaged, "ok-mgmt")
	if len(api.requests) != 12 {
		t.Fatalf("requests=%d, want six GETs then six POSTs", len(api.requests))
	}
	for index, create := range plan.Creates {
		if api.requests[index].method != http.MethodGet || api.requests[index].path != create.ObjectPath {
			t.Fatalf("preflight %d differs: %#v", index, api.requests[index])
		}
		if api.requests[index+6].method != http.MethodPost || api.requests[index+6].path != create.CollectionPath || digest.SHA256(api.requests[index+6].body) != create.ObjectDigest {
			t.Fatalf("create %d differs: %#v", index, api.requests[index+6])
		}
	}
	public, _ := json.Marshal(receipt)
	if bytes.Contains(public, []byte("installer-token")) || bytes.Contains(public, []byte("runtime-uid")) {
		t.Fatal("receipt disclosed credential or raw runtime identity")
	}
}

func TestVerifyRuntimeCreatedNetworkPolicyAcceptsOnlyOmittedEmptyEgress(t *testing.T) {
	desired := []byte(`{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"ok147-stage-authority","namespace":"openkubes-execution-system"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[],"egress":[]}}`)
	observed := []byte(`{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"ok147-stage-authority","namespace":"openkubes-execution-system","uid":"runtime-uid-123","resourceVersion":"1001"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[]}}`)
	if _, _, err := verifyRuntimeCreatedObject(observed, desired); err != nil {
		t.Fatalf("API-omitted empty egress was rejected: %v", err)
	}

	nonEmpty := []byte(`{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"ok147-stage-authority","namespace":"openkubes-execution-system"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"],"ingress":[],"egress":[{"to":[]}]}}`)
	if _, _, err := verifyRuntimeCreatedObject(observed, nonEmpty); err == nil {
		t.Fatal("API-omitted non-empty egress was accepted")
	}

	serviceDesired := []byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"ok147-stage-authority","namespace":"openkubes-execution-system"},"spec":{"selector":{},"ports":[]}}`)
	serviceObserved := []byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"ok147-stage-authority","namespace":"openkubes-execution-system","uid":"runtime-uid-123","resourceVersion":"1001"},"spec":{"selector":{}}}`)
	if _, _, err := verifyRuntimeCreatedObject(serviceObserved, serviceDesired); err == nil {
		t.Fatal("omitted empty list outside the bounded NetworkPolicy field was accepted")
	}
}

func TestRuntimeLauncherStopsZeroWriteAndPreservesPartialWithoutRetry(t *testing.T) {
	packaged := runtimeLauncherPackage(t)
	plan, _ := PlanRuntimeInstallation(packaged, "ok-mgmt")
	t.Run("existing", func(t *testing.T) {
		api := newRuntimeInstallerAPI(t)
		api.objects[plan.Creates[2].ObjectPath] = map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim"}
		launcher := newRuntimeLauncher(t, packaged, api)
		receipt, err := launcher.Launch(context.Background())
		if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 {
			t.Fatalf("existing object did not stop zero-write: %#v posts=%d err=%v", receipt, api.posts, err)
		}
	})
	t.Run("partial", func(t *testing.T) {
		api := newRuntimeInstallerAPI(t)
		api.failPost = 4
		launcher := newRuntimeLauncher(t, packaged, api)
		receipt, err := launcher.Launch(context.Background())
		if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || len(receipt.Results) != 3 {
			t.Fatalf("partial prefix differs: %#v %v", receipt, err)
		}
		requests := len(api.requests)
		retry, retryErr := launcher.Launch(context.Background())
		if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || len(api.requests) != requests {
			t.Fatalf("launcher retried: %#v %v", retry, retryErr)
		}
	})
}

func runtimeLauncherPackage(t *testing.T) VerifiedRuntimePackage {
	t.Helper()
	packaged, err := BuildRuntimePackage(runtimePackageFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	return packaged
}

type runtimeInstallerRequest struct {
	method, path string
	body         []byte
}

type runtimeInstallerAPI struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	objects  map[string]map[string]any
	requests []runtimeInstallerRequest
	posts    int
	failPost int
}

func newRuntimeInstallerAPI(t *testing.T) *runtimeInstallerAPI {
	t.Helper()
	api := &runtimeInstallerAPI{t: t, objects: map[string]map[string]any{}}
	api.server = httptest.NewServer(http.HandlerFunc(api.handle))
	t.Cleanup(api.server.Close)
	return api
}

func (api *runtimeInstallerAPI) handle(writer http.ResponseWriter, request *http.Request) {
	api.mu.Lock()
	defer api.mu.Unlock()
	body, _ := io.ReadAll(request.Body)
	api.requests = append(api.requests, runtimeInstallerRequest{method: request.Method, path: request.URL.Path, body: append([]byte(nil), body...)})
	writer.Header().Set("Content-Type", "application/json")
	switch request.Method {
	case http.MethodGet:
		object, exists := api.objects[request.URL.Path]
		if !exists {
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write([]byte(`{"kind":"Status"}`))
			return
		}
		_ = json.NewEncoder(writer).Encode(object)
	case http.MethodPost:
		api.posts++
		if api.failPost > 0 && api.posts == api.failPost {
			writer.WriteHeader(http.StatusConflict)
			_, _ = writer.Write([]byte(`{"kind":"Status"}`))
			return
		}
		var object map[string]any
		if err := json.Unmarshal(body, &object); err != nil {
			api.t.Errorf("decode create: %v", err)
		}
		metadata, _ := object["metadata"].(map[string]any)
		metadata["uid"] = "runtime-uid-123"
		metadata["resourceVersion"] = "1001"
		writer.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(writer).Encode(object)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newRuntimeLauncher(t *testing.T, packaged VerifiedRuntimePackage, api *runtimeInstallerAPI) *KubernetesRuntimeLauncher {
	t.Helper()
	launcher, err := newKubernetesRuntimeLauncher(runtimeInstallerClientConfig{
		Endpoint: api.server.URL, BearerToken: "installer-token", Authority: "ok-mgmt", Client: api.server.Client(),
	}, packaged)
	if err != nil {
		t.Fatal(err)
	}
	return launcher
}
