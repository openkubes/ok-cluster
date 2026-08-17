package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestAggregateEvidenceStageLauncherRequiresRuntimeThenCreatesNineObjects(t *testing.T) {
	material := aggregateEvidenceVerifiedLaunchMaterial(t)
	api := newSubmissionStageLauncherAPI(t)
	launcher := newAggregateEvidenceStageLauncher(t, material, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
	seedAggregateLauncherObject(t, api, launcher.plan.Preflights[1].ObjectPath, launcher.privateInputs.objects[0].raw, "existing-runtime-binding", "1")

	receipt, err := launcher.Launch(context.Background())
	if err != nil || receipt.State != "LAUNCHED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 10 {
		t.Fatalf("aggregate evidence launch failed: %#v %v", receipt, err)
	}
	if len(api.requests) != 19 || api.posts != 9 {
		t.Fatalf("requests=%d posts=%d, want ten GETs then nine POSTs", len(api.requests), api.posts)
	}
	for index := 0; index < 10; index++ {
		if request := api.requests[index]; request.method != "GET" || request.path != launcher.plan.Preflights[index].ObjectPath {
			t.Fatalf("preflight %d differs: %#v", index+1, request)
		}
	}
	for index, create := range launcher.plan.Creates {
		request := api.requests[index+10]
		if request.method != "POST" || request.path != create.CollectionPath || digest.SHA256(request.body) != create.ObjectDigest {
			t.Fatalf("create %d differs: %#v %#v", index+1, request, create)
		}
	}
	for index, result := range receipt.Results {
		if result.Order != index+1 || result.ObjectState != map[bool]string{true: "EXISTING_VERIFIED", false: "CREATED"}[result.Order == 2] {
			t.Fatalf("result %d differs: %#v", index+1, result)
		}
	}
	if launcher.plan.Creates[len(launcher.plan.Creates)-1].Kind != "Job" || launcher.plan.Creates[len(launcher.plan.Creates)-2].Phase != "private-capability" {
		t.Fatal("aggregate evidence Job was not held behind the private capability input")
	}
	public, _ := json.Marshal(receipt)
	for _, secret := range launcher.secrets {
		if bytes.Contains(public, secret.token) || bytes.Contains(public, secret.raw) {
			t.Fatal("aggregate evidence launch receipt exposed credential material")
		}
	}

	again := newAggregateEvidenceStageLauncher(t, material, api, time.Date(2026, 8, 16, 12, 2, 0, 0, time.UTC))
	againReceipt, err := again.Launch(context.Background())
	if err != nil || againReceipt.State != "ALREADY_LAUNCHED" || againReceipt.MutationState != "NOT_ATTEMPTED" || len(againReceipt.Results) != 10 || api.posts != 9 {
		t.Fatalf("exact existing aggregate evidence set not accepted: %#v %v", againReceipt, err)
	}
}

func TestAggregateEvidenceStageLauncherStopsZeroWriteWithoutRequiredRuntimeBinding(t *testing.T) {
	material := aggregateEvidenceVerifiedLaunchMaterial(t)
	api := newSubmissionStageLauncherAPI(t)
	launcher := newAggregateEvidenceStageLauncher(t, material, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
	receipt, err := launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || len(api.requests) != 10 || api.posts != 0 {
		t.Fatalf("missing runtime binding did not stop zero-write: %#v %v", receipt, err)
	}
}

func TestAggregateEvidenceStageLauncherStopsOnPartialStateAndCreateFailure(t *testing.T) {
	material := aggregateEvidenceVerifiedLaunchMaterial(t)
	for name, prepare := range map[string]func(*testing.T, *submissionStageLauncherAPI, *KubernetesAggregateEvidenceStageLauncher){
		"partial state": func(t *testing.T, api *submissionStageLauncherAPI, launcher *KubernetesAggregateEvidenceStageLauncher) {
			seedAggregateLauncherObject(t, api, launcher.plan.Preflights[1].ObjectPath, launcher.privateInputs.objects[0].raw, "runtime-binding", "1")
			seedAggregateLauncherObject(t, api, launcher.plan.Preflights[2].ObjectPath, launcher.publicObjects[0].raw, "partial-config", "2")
		},
		"create failure": func(t *testing.T, api *submissionStageLauncherAPI, launcher *KubernetesAggregateEvidenceStageLauncher) {
			seedAggregateLauncherObject(t, api, launcher.plan.Preflights[1].ObjectPath, launcher.privateInputs.objects[0].raw, "runtime-binding", "1")
			api.failPost = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			api := newSubmissionStageLauncherAPI(t)
			launcher := newAggregateEvidenceStageLauncher(t, material, api, time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC))
			prepare(t, api, launcher)
			receipt, err := launcher.Launch(context.Background())
			if err == nil {
				t.Fatal("unsafe aggregate evidence launch succeeded")
			}
			if name == "partial state" && (receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0) {
				t.Fatalf("partial state did not stop zero-write: %#v", receipt)
			}
			if name == "create failure" && (receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED_UNKNOWN" || api.posts != 1) {
				t.Fatalf("create failure did not preserve partial state: %#v", receipt)
			}
		})
	}
}

func TestOpenAggregateEvidenceStageLaunchMaterialRequiresExactCandidate(t *testing.T) {
	config, _ := aggregateEvidenceStageLaunchMaterialConfig(t)
	installerToken := []byte("aggregate-installer-token-v1")
	ca := testCA(t)
	config.Candidate.CABundleDigest = digest.SHA256(ca)
	config.Candidate.InstallerTokenDigest = digest.SHA256(installerToken)
	material, err := BuildAggregateEvidenceStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := material.CandidateReceipt()
	root := t.TempDir()
	tokenPath, caPath := filepath.Join(root, "installer-token"), filepath.Join(root, "ca.crt")
	if err := os.WriteFile(tokenPath, installerToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	open := AggregateEvidenceStageLaunchOpenConfig{
		Authority: KubernetesAuthorityConfig{
			Endpoint: config.Candidate.AuthorityEndpoint, AuthorityIdentity: "ok-mgmt",
			TokenFile: tokenPath, CAFile: caPath, CABundleDigest: config.Candidate.CABundleDigest,
		},
		Clock:                   func() time.Time { return time.Date(2026, 8, 16, 12, 1, 0, 0, time.UTC) },
		ExpectedCandidateDigest: candidate.CandidateDigest,
	}
	if _, err := material.Open(open); err != nil {
		t.Fatal(err)
	}
	open.ExpectedCandidateDigest = digest.SHA256([]byte("foreign"))
	if _, err := material.Open(open); err == nil {
		t.Fatal("foreign aggregate evidence candidate digest accepted")
	}
}

func aggregateEvidenceVerifiedLaunchMaterial(t *testing.T) VerifiedAggregateEvidenceStageLaunchMaterial {
	t.Helper()
	config, _ := aggregateEvidenceStageLaunchMaterialConfig(t)
	material, err := BuildAggregateEvidenceStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func newAggregateEvidenceStageLauncher(t *testing.T, material VerifiedAggregateEvidenceStageLaunchMaterial, api *submissionStageLauncherAPI, now time.Time) *KubernetesAggregateEvidenceStageLauncher {
	t.Helper()
	launcher, err := newKubernetesAggregateEvidenceStageLauncher(submissionStageLauncherClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token",
		AuthorityIdentity: "ok-mgmt", Client: api.client(), Clock: func() time.Time { return now },
		ValidUntil: time.Date(2026, 8, 16, 12, 15, 0, 0, time.UTC),
	}, material.packaged, material.credentials, material.privateInputs, material.runtime)
	if err != nil {
		t.Fatal(err)
	}
	return launcher
}

func seedAggregateLauncherObject(t *testing.T, api *submissionStageLauncherAPI, path string, raw []byte, uid, resourceVersion string) {
	t.Helper()
	object := decodeCapabilityJSONForTest(t, raw)
	metadata := object["metadata"].(map[string]any)
	metadata["uid"], metadata["resourceVersion"] = uid, resourceVersion
	api.objects[path] = object
}
