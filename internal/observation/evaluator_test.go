package observation

import (
	"os"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
)

func TestPolicyFromContractAndAllTrue(t *testing.T) {
	policy := testPolicy(t)
	if policy.IntentRevision != testContract(t).NormalizedDigest || len(policy.Required) != 4 {
		t.Fatalf("unexpected policy: %#v", policy)
	}
	result, err := Evaluate(policy, completeBundle(policy))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := result.Receipt()
	if err != nil || receipt.Ready != "True" || receipt.Reason != "AllRequiredConditionsSatisfied" {
		t.Fatalf("unexpected aggregate: %#v %v", receipt, err)
	}
	if evidenceDigest, err := result.EvidenceDigest(); err != nil || !validDigest(evidenceDigest) {
		t.Fatalf("invalid result digest: %q %v", evidenceDigest, err)
	}
}

func TestEvaluateFailsClosedForMissingStaleForeignRevisionAndConflict(t *testing.T) {
	for name, mutate := range map[string]func(*Policy, *Bundle){
		"missing": func(_ *Policy, bundle *Bundle) {
			bundle.Evidence = bundle.Evidence[:3]
		},
		"stale generation": func(_ *Policy, bundle *Bundle) {
			bundle.Evidence[0].ObservedGeneration = 1
			bundle.Evidence[0].Generation = 2
		},
		"foreign Cluster UID": func(_ *Policy, bundle *Bundle) {
			bundle.Evidence[0].SourceUID = "foreign-cluster-uid"
		},
		"wrong enablement revision": func(_ *Policy, bundle *Bundle) {
			bundle.Evidence[2].ObservedRevision = "sha256:" + strings.Repeat("9", 64)
		},
		"conflicting authority": func(_ *Policy, bundle *Bundle) {
			bundle.Evidence = append(bundle.Evidence, bundle.Evidence[1])
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := testPolicy(t)
			bundle := completeBundle(policy)
			mutate(&policy, &bundle)
			result, err := Evaluate(policy, bundle)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := result.Receipt()
			if err != nil || receipt.Ready == "True" {
				t.Fatalf("unsafe aggregate: %#v %v", receipt, err)
			}
		})
	}
}

func TestEvaluateCurrentFailurePrecedesUnknown(t *testing.T) {
	policy := testPolicy(t)
	bundle := completeBundle(policy)
	bundle.Evidence[0].Status = "False"
	bundle.Evidence[0].Reason = "InfrastructureNotReady"
	bundle.Evidence = bundle.Evidence[:3]
	result, err := Evaluate(policy, bundle)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "False" || receipt.Reason != "RequiredConditionFailed" {
		t.Fatalf("False did not precede Unknown: %#v", receipt)
	}
}

func TestEvaluateRejectsInventedGenerationAndMalformedEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*Bundle){
		"invented generation":       func(bundle *Bundle) { bundle.Evidence[2].Generation = 1 },
		"invalid digest":            func(bundle *Bundle) { bundle.Evidence[0].EvidenceDigest = "sha256:no" },
		"invalid observed revision": func(bundle *Bundle) { bundle.Evidence[0].ObservedRevision = "sha256:no" },
		"unsupported source":        func(bundle *Bundle) { bundle.Evidence[0].Source = "OpenKubesOperator" },
	} {
		t.Run(name, func(t *testing.T) {
			policy := testPolicy(t)
			bundle := completeBundle(policy)
			mutate(&bundle)
			if _, err := Evaluate(policy, bundle); err == nil {
				t.Fatal("malformed evidence accepted")
			}
		})
	}
}

func testContract(t *testing.T) contract.Result {
	t.Helper()
	raw, err := os.ReadFile("../contract/testdata/ok141-contract-v5.yaml")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("../contract/testdata/ok141-contract-v3.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	result, err := contract.Canonicalize(raw, schema)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testPolicy(t *testing.T) Policy {
	t.Helper()
	policy, err := PolicyFromContract(testContract(t))
	if err != nil {
		t.Fatal(err)
	}
	policy, err = BindTarget(policy, "capi-cluster-uid-1")
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func completeBundle(policy Policy) Bundle {
	digest := "sha256:" + strings.Repeat("a", 64)
	return Bundle{
		Format: BundleFormat, IntentRevision: policy.IntentRevision, EvaluatedAt: "2026-08-16T10:00:01Z",
		Evidence: []Evidence{
			{Type: "InfrastructureReady", Source: "CAPICluster", SourceUID: policy.TargetClusterUID, TargetClusterUID: policy.TargetClusterUID, Status: "True", Reason: "InfrastructureReady", DesiredRevision: policy.IntentRevision, ObservedRevision: policy.IntentRevision, Generation: 2, ObservedGeneration: 2, EvidenceDigest: digest},
			{Type: "ControlPlaneAvailable", Source: "CAPICluster", SourceUID: policy.TargetClusterUID, TargetClusterUID: policy.TargetClusterUID, Status: "True", Reason: "ControlPlaneAvailable", DesiredRevision: policy.IntentRevision, ObservedRevision: policy.IntentRevision, Generation: 2, ObservedGeneration: 2, EvidenceDigest: digest},
			{Type: "NetworkReady", Source: "BoundedNetworkEvaluator", SourceUID: "network-evidence-1", TargetClusterUID: policy.TargetClusterUID, Status: "True", Reason: "NetworkReady", DesiredRevision: policy.EnablementRevision, ObservedRevision: policy.EnablementRevision, EvidenceDigest: digest},
			{Type: "PlatformReady", Source: "BoundedPlatformEvaluator", SourceUID: "platform-evidence-1", TargetClusterUID: policy.TargetClusterUID, Status: "True", Reason: "PlatformReady", DesiredRevision: policy.PlatformRevision, ObservedRevision: policy.PlatformRevision, EvidenceDigest: digest},
		},
	}
}
