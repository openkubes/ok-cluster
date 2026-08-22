package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestObservabilityCollectorRuntimeAuthorityPackageIsExact(t *testing.T) {
	packaged := collectorRuntimeAuthorityPackageFixture(t)
	receipt, err := packaged.Receipt()
	if err != nil || receipt.Format != ObservabilityCollectorRuntimeAuthorityPackageFormat || receipt.State != "VERIFIED" ||
		len(receipt.ObjectDigests) != 5 || receipt.MutationAllowed || receipt.PackageDigest != receipt.ManifestDigest {
		t.Fatalf("unexpected collector runtime authority package: %#v %v", receipt, err)
	}
	plan, err := PlanObservabilityCollectorRuntimeAuthorityInstallation(packaged)
	if err != nil || plan.Format != ObservabilityCollectorRuntimeAuthorityPlanFormat || len(plan.Creates) != 5 || plan.MutationAllowed {
		t.Fatalf("unexpected collector runtime authority plan: %#v %v", plan, err)
	}
	wantKinds := []string{"Namespace", "ServiceAccount", "ServiceAccount", "Role", "RoleBinding"}
	for index, create := range plan.Creates {
		if create.Order != index+1 || create.Kind != wantKinds[index] || create.PreflightMethod != http.MethodGet || create.CreateMethod != http.MethodPost || create.ObjectPath == "" || create.CollectionPath == "" {
			t.Fatalf("unexpected collector runtime authority create %d: %#v", index+1, create)
		}
	}
}

func TestObservabilityCollectorRuntimeAuthorityPackageFailsClosed(t *testing.T) {
	raw := collectorRuntimeAuthorityManifest(t)
	target := digest.SHA256([]byte("collector-runtime-target"))
	tests := map[string][]byte{
		"automatic token":  bytes.Replace(raw, []byte("automountServiceAccountToken: false"), []byte("automountServiceAccountToken: true"), 1),
		"wildcard verb":    bytes.Replace(raw, []byte("verbs: [get, create]"), []byte("verbs: ['*']"), 1),
		"foreign subject":  bytes.Replace(raw, []byte("name: ok147-observability-collector-installer\n    namespace: openkubes-execution-system"), []byte("name: foreign\n    namespace: openkubes-execution-system"), 1),
		"extra permission": bytes.Replace(raw, []byte("verbs: [get, create]\n---"), []byte("verbs: [get, create]\n  - apiGroups: ['']\n    resources: [pods]\n    verbs: [delete]\n---"), 1),
	}
	for name, changed := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildObservabilityCollectorRuntimeAuthorityPackage(ObservabilityCollectorRuntimeAuthorityPackageConfig{
				Manifest: changed, ExpectedManifestDigest: digest.SHA256(changed), TargetIdentityDigest: target,
			}); err == nil {
				t.Fatal("unsafe collector runtime authority package was accepted")
			}
		})
	}
	if _, err := BuildObservabilityCollectorRuntimeAuthorityPackage(ObservabilityCollectorRuntimeAuthorityPackageConfig{
		Manifest: raw, ExpectedManifestDigest: digest.SHA256([]byte("foreign")), TargetIdentityDigest: target,
	}); err == nil {
		t.Fatal("changed collector runtime authority manifest digest was accepted")
	}
}

func TestObservabilityCollectorRuntimeAuthorityInstallerPreflightsAndCreatesOnce(t *testing.T) {
	packaged := collectorRuntimeAuthorityPackageFixture(t)
	receipt, _ := packaged.Receipt()
	api := &collectorRuntimeAuthorityAPI{}
	installer, err := newKubernetesObservabilityCollectorRuntimeAuthorityInstaller(observabilityCollectorRuntimeAuthorityClientConfig{
		Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", TargetIdentity: receipt.TargetIdentityDigest,
		Client: &http.Client{Transport: api},
	}, packaged)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := installer.Install(context.Background())
	if err != nil || installed.State != "INSTALLED" || installed.MutationState != "ATTEMPTED" || len(installed.Results) != 5 || api.posts != 5 || len(api.requests) != 10 {
		t.Fatalf("collector runtime authority was not installed exactly: %#v api=%#v err=%v", installed, api, err)
	}
	for index := 0; index < 5; index++ {
		if !strings.HasPrefix(api.requests[index], "GET ") || !strings.HasPrefix(api.requests[index+5], "POST ") {
			t.Fatalf("global preflight barrier differs: %#v", api.requests)
		}
	}
	if _, err := installer.Install(context.Background()); err == nil || api.posts != 5 {
		t.Fatal("collector runtime authority installer retried")
	}
}

func TestObservabilityCollectorRuntimeAuthorityInstallerStopsZeroWriteAndPartial(t *testing.T) {
	packaged := collectorRuntimeAuthorityPackageFixture(t)
	receipt, _ := packaged.Receipt()
	for name, api := range map[string]*collectorRuntimeAuthorityAPI{
		"existing": {existingGET: 2},
		"partial":  {failPOST: 2},
	} {
		t.Run(name, func(t *testing.T) {
			installer, err := newKubernetesObservabilityCollectorRuntimeAuthorityInstaller(observabilityCollectorRuntimeAuthorityClientConfig{
				Endpoint: "https://127.0.0.1:12345", BearerToken: "workload-admin", TargetIdentity: receipt.TargetIdentityDigest,
				Client: &http.Client{Transport: api},
			}, packaged)
			if err != nil {
				t.Fatal(err)
			}
			result, err := installer.Install(context.Background())
			if err == nil {
				t.Fatal("collector runtime authority failure was accepted")
			}
			if name == "existing" && (result.State != "STOPPED_ZERO_WRITE" || api.posts != 0) {
				t.Fatalf("existing object crossed zero-write barrier: %#v %#v", result, api)
			}
			if name == "partial" && (result.State != "STOPPED_PARTIAL_OR_UNKNOWN" || len(result.Results) != 1 || api.posts != 2) {
				t.Fatalf("partial state was not retained: %#v %#v", result, api)
			}
		})
	}
}

func TestOpenObservabilityCollectorRuntimeAuthorityInstallerBindsWorkloadTarget(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	runtime := targetAccessRuntime(t, fixture.plan)
	binding, err := loadWorkloadAuthorityBinding(runtime.Workload.Path, runtime.Workload.ExpectedBindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	raw := collectorRuntimeAuthorityManifest(t)
	packaged, err := BuildObservabilityCollectorRuntimeAuthorityPackage(ObservabilityCollectorRuntimeAuthorityPackageConfig{
		Manifest: raw, ExpectedManifestDigest: digest.SHA256(raw), TargetIdentityDigest: digest.SHA256([]byte(binding.TargetClusterUID)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKubernetesObservabilityCollectorRuntimeAuthorityInstaller(runtime.Workload, packaged); err != nil {
		t.Fatal(err)
	}
	foreign, err := BuildObservabilityCollectorRuntimeAuthorityPackage(ObservabilityCollectorRuntimeAuthorityPackageConfig{
		Manifest: raw, ExpectedManifestDigest: digest.SHA256(raw), TargetIdentityDigest: digest.SHA256([]byte("foreign")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKubernetesObservabilityCollectorRuntimeAuthorityInstaller(runtime.Workload, foreign); err == nil {
		t.Fatal("foreign target opened collector runtime authority installer")
	}
}

func collectorRuntimeAuthorityPackageFixture(t *testing.T) VerifiedObservabilityCollectorRuntimeAuthorityPackage {
	t.Helper()
	raw := collectorRuntimeAuthorityManifest(t)
	packaged, err := BuildObservabilityCollectorRuntimeAuthorityPackage(ObservabilityCollectorRuntimeAuthorityPackageConfig{
		Manifest: raw, ExpectedManifestDigest: digest.SHA256(raw), TargetIdentityDigest: digest.SHA256([]byte("collector-runtime-target")),
	})
	if err != nil {
		t.Fatal(err)
	}
	return packaged
}

func collectorRuntimeAuthorityManifest(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/observability-collector-runtime-authority.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type collectorRuntimeAuthorityAPI struct {
	requests    []string
	posts       int
	existingGET int
	failPOST    int
}

func (api *collectorRuntimeAuthorityAPI) RoundTrip(request *http.Request) (*http.Response, error) {
	api.requests = append(api.requests, request.Method+" "+request.URL.Path)
	if request.Header.Get("Authorization") != "Bearer workload-admin" {
		return targetCredentialTestResponse(http.StatusUnauthorized, map[string]any{"kind": "Status"}), nil
	}
	if request.Method == http.MethodGet {
		getIndex := len(api.requests)
		if api.existingGET == getIndex {
			return targetCredentialTestResponse(http.StatusOK, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "foreign"}}), nil
		}
		return targetCredentialTestResponse(http.StatusNotFound, map[string]any{"kind": "Status"}), nil
	}
	api.posts++
	if api.failPOST == api.posts {
		return targetCredentialTestResponse(http.StatusForbidden, map[string]any{"kind": "Status"}), nil
	}
	body, _ := io.ReadAll(request.Body)
	var object map[string]any
	if json.Unmarshal(body, &object) != nil {
		return targetCredentialTestResponse(http.StatusBadRequest, map[string]any{"kind": "Status"}), nil
	}
	metadata := object["metadata"].(map[string]any)
	metadata["uid"] = "collector-runtime-uid-" + string(rune('0'+api.posts))
	metadata["resourceVersion"] = "collector-runtime-rv-" + string(rune('0'+api.posts))
	return targetCredentialTestResponse(http.StatusCreated, object), nil
}
