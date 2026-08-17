package runner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestLoadSubmissionStageBundleSelectsBoundProjectionStage(t *testing.T) {
	for _, completedProvider := range []bool{false, true} {
		name := "provider-prerequisites"
		if completedProvider {
			name = "cluster-lifecycle"
		}
		t.Run(name, func(t *testing.T) {
			fixture := submissionBundleFixture(t, completedProvider, "")
			bundle, err := LoadSubmissionStageBundle(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := bundle.Decision()
			if err != nil || decision.StageID != name || decision.State != "NEXT" || !decision.RequiresAuthorization {
				t.Fatalf("unexpected decision: %#v %v", decision, err)
			}
		})
	}
}

func TestLoadSubmissionStageBundleRejectsImplicitPrefixAndProjectionMismatch(t *testing.T) {
	fixture := submissionBundleFixture(t, false, "")
	fixture.config.Receipts = nil
	if _, err := LoadSubmissionStageBundle(fixture.config); err == nil {
		t.Fatal("implicit empty receipt prefix was accepted")
	}

	fixture = submissionBundleFixture(t, false, bundleSHA("f"))
	if _, err := LoadSubmissionStageBundle(fixture.config); err == nil || !strings.Contains(err.Error(), "differs from verified artifact") {
		t.Fatalf("projection digest mismatch was accepted: %v", err)
	}

	fixture = submissionBundleFixture(t, false, "")
	fixture.config.ExpectedStageID = "cluster-lifecycle"
	if _, err := LoadSubmissionStageBundle(fixture.config); err == nil || !strings.Contains(err.Error(), "differs from the independently expected stage") {
		t.Fatalf("foreign cursor stage was accepted: %v", err)
	}
}

func TestSubmissionStageBundleOpenIsOfflineAndRequiresDistinctCredentials(t *testing.T) {
	fixture := submissionBundleFixture(t, false, "")
	bundle, err := LoadSubmissionStageBundle(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	runtime := submissionBundleRuntime(t, fixture.plan, "provider-prerequisites")
	bound, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !bound.verified {
		t.Fatal("opened runtime is not marked verified")
	}

	authorityToken, err := os.ReadFile(runtime.Authority.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtime.Ledger.TokenFile, authorityToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Open(runtime); err == nil {
		t.Fatal("shared ledger and writer credential was accepted")
	}
	if _, err := (VerifiedSubmissionStageBundle{}).Open(runtime); err == nil {
		t.Fatal("unverified bundle was opened")
	}
}

type submissionBundleTestFixture struct {
	config SubmissionStageBundleConfig
	plan   stageplan.Binding
}

func submissionBundleFixture(t *testing.T, completedProvider bool, overrideProviderDigest string) submissionBundleTestFixture {
	t.Helper()
	root := t.TempDir()
	at := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	identity := contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"}
	revision := bundleSHA("a")
	infra := []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: disposable-ok147\n  annotations:\n    openkubes.io/contract-name: disposable-ok147\n    openkubes.io/contract-namespace: disposable-ok147\n    openkubes.io/intent-revision: " + revision + "\n")
	management := []byte("apiVersion: cluster.x-k8s.io/v1beta2\nkind: Cluster\nmetadata:\n  name: disposable-ok147\n  namespace: disposable-ok147\n  annotations:\n    openkubes.io/contract-name: disposable-ok147\n    openkubes.io/contract-namespace: disposable-ok147\n    openkubes.io/intent-revision: " + revision + "\nspec:\n  clusterNetwork:\n    services:\n      cidrBlocks: [10.100.0.0/20]\n")
	authority := mustJSON(t, map[string]any{
		"format": "ok141-contract-to-capi-projection/v2", "contractIdentity": identity, "intentRevision": revision,
		"infrastructurePlane": map[string]any{
			"identity": "ok-infra", "role": "provider-runtime-and-golden-image-prerequisites",
			"resources": []map[string]any{{"apiVersion": "v1", "kind": "Namespace", "name": "disposable-ok147"}},
		},
		"managementPlane": map[string]any{
			"identity": "ok-mgmt", "role": "single-lifecycle-writer",
			"resources": []map[string]any{{"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster", "namespace": "disposable-ok147", "name": "disposable-ok147"}},
		},
		"providerAccess": map[string]any{}, "excludedRendererArtifacts": []any{},
	})
	writeBundleFile(t, root, "authority-map.json", authority)
	writeBundleFile(t, root, "ok-infra-prerequisites.yaml", infra)
	writeBundleFile(t, root, "ok-mgmt-lifecycle.yaml", management)

	manifest := mustJSON(t, map[string]any{
		"format": "ok141-contract-to-capi-projection/v2", "R": revision, "authorizationState": "NO-GO",
		"artifacts": map[string]any{
			"authority-map.json": digest.SHA256(authority), "ok-infra-prerequisites.yaml": digest.SHA256(infra), "ok-mgmt-lifecycle.yaml": digest.SHA256(management),
		},
		"objectSets": map[string]any{
			"okInfraPrerequisites": map[string]any{"count": 1, "digest": bundleSHA("1")},
			"okMgmtLifecycle":      map[string]any{"count": 1, "digest": bundleSHA("2")},
		},
		"providerAccess": map[string]any{}, "source": map[string]any{},
	})
	manifestPath := writeBundleFile(t, root, "projection-manifest.json", manifest)

	providerDigest := digest.SHA256(infra)
	if overrideProviderDigest != "" {
		providerDigest = overrideProviderDigest
	}
	expected := stageplan.Expected{
		ContractIdentity: identity, IntentRevision: revision, EnablementRevision: bundleSHA("b"), PlatformRevision: bundleSHA("c"), ExecutionFixture: bundleSHA("d"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
	}
	planPath := writeBundleFile(t, root, "staged-plan.json", submissionBundlePlan(t, expected, providerDigest, digest.SHA256(management)))
	plan, err := stageplan.Load(planPath, expected)
	if err != nil {
		t.Fatal(err)
	}
	receipts := []StageReceiptSource{}
	predecessors := []stagereceipt.Verified{}
	stageID := "provider-prerequisites"
	if completedProvider {
		provider, err := stagereceipt.New(plan, "provider-prerequisites", []stagereceipt.Verified{}, "SUCCEEDED", "ATTEMPTED", bundleSHA("8"), bundleSHA("9"), at.Add(-2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := provider.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		receiptDigest, err := provider.Digest()
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, StageReceiptSource{Path: writeBundleFile(t, root, "provider-receipt.json", raw), Digest: receiptDigest})
		predecessors = []stagereceipt.Verified{provider}
		stageID = "cluster-lifecycle"
	}
	grantPath, keyPath := writeSubmissionStageGrant(t, root, plan, stageID, predecessors, at)
	return submissionBundleTestFixture{
		config: SubmissionStageBundleConfig{
			ExpectedStageID: stageID, PlanPath: planPath, PlanExpected: expected, Receipts: receipts, GrantPath: grantPath, GrantPublicKeyPath: keyPath,
			ProjectionManifestPath: manifestPath, ProjectionRoot: root, EvaluationTime: at,
		},
		plan: plan,
	}
}

func submissionBundlePlan(t *testing.T, expected stageplan.Expected, providerDigest, managementDigest string) []byte {
	t.Helper()
	ids := []string{"provider-prerequisites", "cluster-lifecycle", "lifecycle-observation", "enablement", "network-observation", "runtime-binding", "target-access", "target-credential", "target-registration", "platform-applications", "platform-observation", "aggregate-evidence"}
	kinds := []string{"Submission", "Submission", "Observation", "Submission", "Observation", "Binding", "Submission", "Credential", "Submission", "Submission", "Observation", "Evaluation"}
	authorities := []string{"infrastructure", "management", "management", "management", "workload", "runner", "workload", "workload", "gitops", "gitops", "gitops", "runner"}
	operations := []string{"CreateProviderPrerequisites", "CreateCluster", "", "CreateEnablement", "", "", "CreateTargetAccess", "IssueTargetCredential", "RegisterTarget", "CreatePlatformApplications", "", ""}
	stages := make([]map[string]any, len(ids))
	for index := range ids {
		requires := []string{}
		if index > 0 {
			requires = []string{ids[index-1]}
		}
		name, inputDigest := "stage."+ids[index], bundleSHA(string("abcdef012345"[index]))
		if index == 0 {
			name, inputDigest = "projection.provider-prerequisites", providerDigest
		} else if index == 1 {
			name, inputDigest = "projection.cluster-lifecycle", managementDigest
		}
		stages[index] = map[string]any{
			"id": ids[index], "order": index + 1, "kind": kinds[index], "authority": authorities[index], "requires": requires,
			"inputs": []map[string]any{{"name": name, "digest": inputDigest}},
		}
		if operations[index] != "" {
			stages[index]["grantOperation"] = operations[index]
		}
	}
	return mustJSON(t, map[string]any{
		"format": stageplan.Format, "contractIdentity": expected.ContractIdentity,
		"intentRevision": expected.IntentRevision, "enablementRevision": expected.EnablementRevision, "platformRevision": expected.PlatformRevision, "executionFixture": expected.ExecutionFixture,
		"authorizationState": "NO-GO",
		"authorities":        map[string]any{"infrastructure": expected.InfrastructureAuthority, "management": expected.ManagementAuthority, "gitOps": expected.GitOpsAuthority, "workloadIdentityMode": "capi-cluster-uid/v1", "runnerIdentityMode": "bounded-job/v1"},
		"stages":             stages,
	})
}

func writeSubmissionStageGrant(t *testing.T, root string, plan stageplan.Binding, stageID string, predecessors []stagereceipt.Verified, at time.Time) (string, string) {
	t.Helper()
	stage, stageDigest, err := plan.Stage(stageID)
	if err != nil {
		t.Fatal(err)
	}
	links := make([]authorization.StagePredecessor, len(predecessors))
	for index, predecessor := range predecessors {
		receipt, err := predecessor.Receipt()
		if err != nil {
			t.Fatal(err)
		}
		receiptDigest, err := predecessor.Digest()
		if err != nil {
			t.Fatal(err)
		}
		links[index] = authorization.StagePredecessor{StageID: receipt.StageID, OutcomeDigest: receiptDigest}
	}
	payload := authorization.StagePayload{
		Audience: authorization.StageAudience, GrantID: "ok147-bundle-stage-01", Decision: "ALLOW",
		PlanDigest: plan.PlanDigest, ContractIdentity: plan.ContractIdentity, ContractRevision: plan.IntentRevision,
		EnablementRevision: plan.EnablementRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		StageID: stage.ID, StageOrder: stage.Order, StageDigest: stageDigest, Operation: stage.GrantOperation, Authority: stage.Authority,
		Predecessors: links, NotBefore: at.Add(-time.Minute).Format(time.RFC3339), NotAfter: at.Add(20 * time.Minute).Format(time.RFC3339), MaxUses: 1,
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := authorization.StageSigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope := mustJSON(t, map[string]any{
		"format": authorization.StageFormat, "payload": payload,
		"signature": map[string]any{"algorithm": "Ed25519", "keyId": digest.SHA256(publicKey), "value": base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed))},
	})
	return writeBundleFile(t, root, "stage-grant.json", envelope), writeBundleFile(t, root, "stage-authority.pub", []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"))
}

func submissionBundleRuntime(t *testing.T, plan stageplan.Binding, stageID string) SubmissionStageRuntimeConfig {
	t.Helper()
	root := t.TempDir()
	caPath := writeBundleFile(t, root, "ca.crt", testCA(t))
	ledgerToken := writeBundleFile(t, root, "ledger-token", []byte("bundle-ledger-token"))
	authorityToken := writeBundleFile(t, root, "authority-token", []byte("bundle-authority-token"))
	authority, endpoint := plan.Authorities.Infrastructure, "https://192.0.2.11:6443"
	if stageID == "cluster-lifecycle" {
		authority, endpoint = plan.Authorities.Management, "https://192.0.2.12:6443"
	}
	return SubmissionStageRuntimeConfig{
		Ledger:    KubernetesLedgerConfig{Endpoint: "https://192.0.2.12:6443", Namespace: "openkubes-execution-system", TokenFile: ledgerToken, CAFile: caPath},
		Authority: KubernetesAuthorityConfig{Endpoint: endpoint, AuthorityIdentity: authority, TokenFile: authorityToken, CAFile: caPath},
		Clock:     func() time.Time { return time.Date(2026, 8, 16, 14, 1, 0, 0, time.UTC) },
	}
}

func writeBundleFile(t *testing.T, root, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func bundleSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
