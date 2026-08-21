package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestKubernetesLifecycleWorkloadAuthorityMaterializerUsesExactStageFiveAuthority(t *testing.T) {
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
	if receipt, err := executor.Run(context.Background()); err != nil || receipt.State != "SUCCEEDED" {
		t.Fatalf("pre-runtime execution did not reach materializer: %#v err=%v materializer=%v requests=%v", receipt, err, materializeErr, requests)
	}
	if !reflect.DeepEqual(requests, wantPaths) {
		t.Fatalf("materializer request surface differs: got=%v want=%v", requests, wantPaths)
	}
	for _, path := range []string{materialized.KubeconfigFile, materialized.CAFile, materialized.Path} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("private material is not a regular 0600 file: %s %#v %v", path, info, err)
		}
	}
	resolver, err := OpenWorkloadAuthorityFileResolver(materialized)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := resolver.ResolveWorkloadAuthority(context.Background(), networkPolicyForMaterializedAuthority(config, "11111111-1111-4111-8111-111111111111"))
	if err != nil || authority.Endpoint != workloadEndpoint || authority.TokenFile != "" || authority.KubeconfigFile != materialized.KubeconfigFile {
		t.Fatalf("materialized workload authority is not replayable: %#v err=%v", authority, err)
	}
	if _, err := materializer.ResolvePreRuntimeWorkloadAuthority(context.Background(), StageResumeConfig{}); err == nil {
		t.Fatal("single-use materializer resolved twice")
	}
}

func networkPolicyForMaterializedAuthority(config PreRuntimeExecutionConfig, targetUID string) observation.Policy {
	return observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: config.PlanExpected.IntentRevision,
		EnablementRevision: config.PlanExpected.EnablementRevision, PlatformRevision: config.PlanExpected.PlatformRevision,
		TargetClusterUID: targetUID, Required: []string{"NetworkReady"},
	}
}
