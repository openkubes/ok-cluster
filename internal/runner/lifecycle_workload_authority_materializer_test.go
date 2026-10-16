package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestKubernetesLifecycleWorkloadAuthorityMaterializerRejectsBeforeAPIContact(t *testing.T) {
	workloadCA, workloadCertificate, workloadKey := testClientCredential(t)
	workloadEndpoint := "https://192.0.2.90:6443"
	kubeconfig := testClientKubeconfig(workloadEndpoint, workloadCA, workloadCertificate, workloadKey)
	wantPaths := []string{
		"/apis/cluster.x-k8s.io/v1beta2/namespaces/disposable-ok147/clusters/disposable-ok147",
		"/api/v1/namespaces/disposable-ok147/secrets/disposable-ok147-kubeconfig",
	}
	requests := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.URL.Path)
		if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.Header.Get("Authorization") != "Bearer bounded-management-token" {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case wantPaths[0]:
			_ = json.NewEncoder(response).Encode(map[string]any{
				"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster",
				"metadata": map[string]any{
					"name": "disposable-ok147", "namespace": "disposable-ok147",
					"uid": "11111111-1111-4111-8111-111111111111", "resourceVersion": "42",
				},
				"spec": map[string]any{"controlPlaneEndpoint": map[string]any{"host": "192.0.2.90", "port": 6443}},
			})
		case wantPaths[1]:
			_ = json.NewEncoder(response).Encode(map[string]any{
				"apiVersion": "v1", "kind": "Secret", "type": "cluster.x-k8s.io/secret",
				"metadata": map[string]any{
					"name": "disposable-ok147-kubeconfig", "namespace": "disposable-ok147",
					"uid": "22222222-2222-4222-8222-222222222222", "resourceVersion": "43",
				},
				"data": map[string]string{"value": base64.StdEncoding.EncodeToString(kubeconfig)},
			})
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config, factories, _, _ := preRuntimeExecutionFixture(t)
	privateRoot := t.TempDir()
	if err := os.Chmod(privateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	managementCA := filepath.Join(privateRoot, "management-ca.crt")
	managementToken := filepath.Join(privateRoot, "management-token")
	if err := os.WriteFile(managementCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managementToken, []byte("bounded-management-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	materializer, err := OpenKubernetesLifecycleWorkloadAuthorityMaterializer(KubernetesLifecycleWorkloadAuthorityMaterializerConfig{
		Management: KubernetesAuthorityConfig{
			Endpoint: server.URL, AuthorityIdentity: "ok-mgmt", TokenFile: managementToken, CAFile: managementCA,
		},
		ExpectedManagementAuthority: "ok-mgmt",
		BindingPath:                 filepath.Join(privateRoot, "workload-authority.json"),
		KubeconfigFile:              filepath.Join(privateRoot, "workload.kubeconfig"),
		CAFile:                      filepath.Join(privateRoot, "workload-ca.crt"),
	})
	if err != nil {
		t.Fatal(err)
	}
	original := config.WorkloadAuthority
	var materialized WorkloadAuthorityFileResolverConfig
	var materializeErr error
	config.WorkloadAuthority = PreRuntimeWorkloadAuthorityResolverFunc(func(ctx context.Context, resume StageResumeConfig) (WorkloadAuthorityFileResolverConfig, error) {
		materialized, materializeErr = materializer.ResolvePreRuntimeWorkloadAuthority(ctx, resume)
		if materializeErr != nil {
			return WorkloadAuthorityFileResolverConfig{}, materializeErr
		}
		// The fake stage factories retain their original synthetic authority;
		// this wrapper lets the concrete resolver execute at its real cursor.
		return original.ResolvePreRuntimeWorkloadAuthority(ctx, resume)
	})
	executor, err := openPreRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := executor.Run(context.Background()); err == nil || receipt.State == "SUCCEEDED" || !errors.Is(materializeErr, ErrClientCertificateDisabled) {
		t.Fatalf("unbounded workload bootstrap enabled: %#v err=%v materializer=%v", receipt, err, materializeErr)
	}
	if len(requests) != 0 {
		t.Fatalf("credential bootstrap contacted API before denial: %v", requests)
	}
	if materialized != (WorkloadAuthorityFileResolverConfig{}) {
		t.Fatal("denied bootstrap returned credential material")
	}
	for _, name := range []string{"workload.kubeconfig", "workload-ca.crt", "workload-authority.json"} {
		if _, err := os.Lstat(filepath.Join(privateRoot, name)); !os.IsNotExist(err) {
			t.Fatalf("denied bootstrap wrote %s: %v", name, err)
		}
	}
}

func networkPolicyForMaterializedAuthority(config PreRuntimeExecutionConfig, targetUID string) observation.Policy {
	return observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: config.PlanExpected.IntentRevision,
		EnablementRevision: config.PlanExpected.EnablementRevision, PlatformRevision: config.PlanExpected.PlatformRevision,
		TargetClusterUID: targetUID, Required: []string{"NetworkReady"},
	}
}
