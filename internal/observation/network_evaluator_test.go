package observation

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateNetworkSnapshotProducesCurrentEVIDENCE(t *testing.T) {
	policy, profile, snapshot := validNetworkFixture(t)
	evidence, err := EvaluateNetworkSnapshot(policy, profile, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Type != "NetworkReady" || evidence.Source != "BoundedNetworkEvaluator" || evidence.Status != "True" || evidence.Reason != "NetworkReady" || evidence.TargetClusterUID != policy.TargetClusterUID || evidence.ObservedRevision != policy.EnablementRevision || !validDigest(evidence.EvidenceDigest) {
		t.Fatalf("unexpected network evidence: %#v", evidence)
	}
	bundle := completeBundle(policy)
	bundle.Evidence[2] = evidence
	result, err := Evaluate(policy, bundle)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "True" {
		t.Fatalf("network evidence did not compose: %#v", receipt)
	}
}

func TestEvaluateNetworkSnapshotBindsSemanticProfileIdentity(t *testing.T) {
	policy, profile, snapshot := validNetworkFixture(t)
	first, err := EvaluateNetworkSnapshot(policy, profile, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	profile.MinimumProbeFreshnessSeconds++
	second, err := EvaluateNetworkSnapshot(policy, profile, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "True" || second.Status != "True" || first.EvidenceDigest == second.EvidenceDigest || first.SourceUID == second.SourceUID {
		t.Fatalf("semantic profile change was not bound into evidence: first=%#v second=%#v", first, second)
	}
}

func TestEvaluateNetworkSnapshotFailsClosed(t *testing.T) {
	tests := map[string]struct {
		mutate func(*NetworkSnapshot)
		status string
		reason string
	}{
		"missing E": {
			mutate: func(snapshot *NetworkSnapshot) { snapshot.EnablementRevision = "" },
			status: "Unknown", reason: "RevisionCorrelationUnproven",
		},
		"stale HCP": {
			mutate: func(snapshot *NetworkSnapshot) { snapshot.HCP.StatusObservedGeneration-- },
			status: "Unknown", reason: "EnablementOwnerNotReady",
		},
		"HCP spec mismatch": {
			mutate: func(snapshot *NetworkSnapshot) { snapshot.HCP.SpecDigest = "sha256:" + strings.Repeat("f", 64) },
			status: "False", reason: "EnablementOwnerIdentityMismatch",
		},
		"HCP target not selected": {
			mutate: func(snapshot *NetworkSnapshot) { snapshot.HCP.TargetSelected = false },
			status: "False", reason: "EnablementOwnerIdentityMismatch",
		},
		"multiple HRPs": {
			mutate: func(snapshot *NetworkSnapshot) { snapshot.HRPCount = 2 },
			status: "Unknown", reason: "EnablementReleaseNotReady",
		},
		"node networking pending": {
			mutate: func(snapshot *NetworkSnapshot) { snapshot.Nodes[0].NetworkUnavailable = "True" },
			status: "Unknown", reason: "NodeNetworkNotReady",
		},
		"mutable image mismatch": {
			mutate: func(snapshot *NetworkSnapshot) { snapshot.Components[0].Image = "quay.io/cilium/cilium:v1.19.6" },
			status: "False", reason: "CiliumImageMismatch",
		},
		"rollout stale": {
			mutate: func(snapshot *NetworkSnapshot) { snapshot.Components[0].ObservedGeneration-- },
			status: "Unknown", reason: "CiliumRolloutNotReady",
		},
		"pod coverage differs": {
			mutate: func(snapshot *NetworkSnapshot) { snapshot.AgentPods[1].NodeUID = snapshot.AgentPods[0].NodeUID },
			status: "False", reason: "CiliumNodeCoverageInvalid",
		},
		"functional path failed": {
			mutate: func(snapshot *NetworkSnapshot) {
				snapshot.Probe.Paths[0].StatusPresent, snapshot.Probe.Paths[0].Status = true, "timeout"
			},
			status: "False", reason: "FunctionalProbeFailed",
		},
		"functional path stale": {
			mutate: func(snapshot *NetworkSnapshot) { snapshot.Probe.Paths[0].LastProbed = "2026-08-16T09:55:00Z" },
			status: "False", reason: "FunctionalProbeStale",
		},
		"duplicate functional path": {
			mutate: func(snapshot *NetworkSnapshot) { snapshot.Probe.Paths[1] = snapshot.Probe.Paths[0] },
			status: "False", reason: "FunctionalProbeCoverageInvalid",
		},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			policy, profile, snapshot := validNetworkFixture(t)
			testCase.mutate(&snapshot)
			evidence, err := EvaluateNetworkSnapshot(policy, profile, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != testCase.status || evidence.Reason != testCase.reason || evidence.Status == "True" {
				t.Fatalf("unsafe network result: %#v", evidence)
			}
		})
	}
}

func TestEvaluateNetworkSnapshotUsesBoundedDynamicCacheFreshness(t *testing.T) {
	policy, profile, snapshot := validNetworkFixture(t)
	// 2 * 96.566s probe interval + 60s cache exposure = 253.132s.
	snapshot.Probe.ProbeIntervalMilliseconds = 96566
	snapshot.Probe.Paths[0].LastProbed = "2026-08-16T09:56:00Z" // 240s old.
	evidence, err := EvaluateNetworkSnapshot(policy, profile, snapshot)
	if err != nil || evidence.Status != "True" {
		t.Fatalf("valid cached Cilium path was rejected: %#v %v", evidence, err)
	}
	snapshot.Probe.Paths[0].LastProbed = "2026-08-16T09:55:30Z" // 270s old.
	evidence, err = EvaluateNetworkSnapshot(policy, profile, snapshot)
	if err != nil || evidence.Status != "False" || evidence.Reason != "FunctionalProbeStale" {
		t.Fatalf("stale cached Cilium path was accepted: %#v %v", evidence, err)
	}
}

func TestEvaluateNetworkSnapshotRejectsMalformedUnboundedInput(t *testing.T) {
	for name, mutate := range map[string]func(*NetworkProfile, *NetworkSnapshot){
		"mutable profile image": func(profile *NetworkProfile, _ *NetworkSnapshot) {
			profile.ExpectedImages.CiliumAgent = "quay.io/cilium/cilium:v1.19.6"
		},
		"malformed revision": func(_ *NetworkProfile, snapshot *NetworkSnapshot) {
			snapshot.EnablementRevision = "sha256:no"
		},
		"too many nodes": func(_ *NetworkProfile, snapshot *NetworkSnapshot) {
			snapshot.Nodes = make([]NetworkNode, 101)
		},
		"unbounded probe interval": func(_ *NetworkProfile, snapshot *NetworkSnapshot) {
			snapshot.Probe.ProbeIntervalMilliseconds = 601000
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy, profile, snapshot := validNetworkFixture(t)
			mutate(&profile, &snapshot)
			if _, err := EvaluateNetworkSnapshot(policy, profile, snapshot); err == nil && name != "unbounded probe interval" {
				t.Fatal("malformed network input accepted")
			} else if name == "unbounded probe interval" && err == nil {
				evidence, _ := EvaluateNetworkSnapshot(policy, profile, snapshot)
				if evidence.Status != "False" || evidence.Reason != "FunctionalProbeInvalid" {
					t.Fatalf("unbounded probe interval accepted: %#v", evidence)
				}
			}
		})
	}
}

func validNetworkFixture(t *testing.T) (Policy, NetworkProfile, NetworkSnapshot) {
	t.Helper()
	policy := testPolicy(t)
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	images := NetworkImages{
		CiliumAgent:    "quay.io/cilium/cilium:v1.19.6@sha256:" + strings.Repeat("1", 64),
		CiliumEnvoy:    "quay.io/cilium/cilium-envoy:v1.36.9@sha256:" + strings.Repeat("2", 64),
		CiliumOperator: "quay.io/cilium/operator-generic:v1.19.6@sha256:" + strings.Repeat("3", 64),
	}
	profile := NetworkProfile{
		Format: NetworkProfileFormat, IntentRevision: policy.IntentRevision,
		EnablementRevision: policy.EnablementRevision, ExpectedNodeCount: 2,
		ExpectedHCPSpecDigest: digestA, ExpectedHRPSpecDigest: digestB, ExpectedImages: images,
		MinimumProbeFreshnessSeconds: 120, MaximumProbeIntervalSeconds: 120, CacheExposureSeconds: 60,
	}
	conditions := func(names ...string) []NetworkSourceCondition {
		result := make([]NetworkSourceCondition, 0, len(names))
		for _, name := range names {
			result = append(result, NetworkSourceCondition{Type: name, Status: "True", ObservedGeneration: 4})
		}
		return result
	}
	hcp := NetworkAddonSource{
		UID: "hcp-uid-1", Generation: 4, StatusObservedGeneration: 4, SpecDigest: digestA,
		IntentRevision: policy.IntentRevision, EnablementRevision: policy.EnablementRevision,
		TargetClusterUID: policy.TargetClusterUID, TargetSelected: true,
		Conditions: conditions("Ready", "HelmReleaseProxySpecsUpToDate", "HelmReleaseProxiesReady"),
	}
	hrp := NetworkAddonSource{
		UID: "hrp-uid-1", Generation: 4, StatusObservedGeneration: 4, SpecDigest: digestB,
		IntentRevision: policy.IntentRevision, EnablementRevision: policy.EnablementRevision,
		OwnerUID: hcp.UID, TargetClusterUID: policy.TargetClusterUID, TargetSelected: true,
		ReleaseStatus: "deployed", ReleaseRevision: 1,
		Conditions: conditions("Ready", "HelmReleaseReady"),
	}
	nodes := []NetworkNode{
		{UID: "node-uid-1", ProviderID: "provider://node-1", Ready: "True", NetworkUnavailable: "False", NetworkUnavailableReason: "CiliumIsUp"},
		{UID: "node-uid-2", ProviderID: "provider://node-2", Ready: "True", NetworkUnavailable: "False", NetworkUnavailableReason: "CiliumIsUp"},
	}
	components := []NetworkComponent{
		{ID: "cilium-agent", UID: "component-uid-1", Generation: 3, ObservedGeneration: 3, Desired: 2, Updated: 2, Available: 2, Ready: 2, Image: images.CiliumAgent},
		{ID: "cilium-envoy", UID: "component-uid-2", Generation: 3, ObservedGeneration: 3, Desired: 2, Updated: 2, Available: 2, Ready: 2, Image: images.CiliumEnvoy},
		{ID: "cilium-operator", UID: "component-uid-3", Generation: 3, ObservedGeneration: 3, Desired: 1, Updated: 1, Available: 1, Ready: 1, Image: images.CiliumOperator},
	}
	pods := []NetworkAgentPod{
		{UID: "pod-uid-1", NodeUID: nodes[0].UID, Phase: "Running", Ready: true},
		{UID: "pod-uid-2", NodeUID: nodes[1].UID, Phase: "Running", Ready: true},
	}
	paths := make([]NetworkProbePath, 0, 8)
	for _, node := range nodes {
		for _, scope := range []string{"host", "health-endpoint"} {
			for _, protocol := range []string{"http", "icmp"} {
				paths = append(paths, NetworkProbePath{NodeUID: node.UID, Scope: scope, Protocol: protocol, LastProbed: "2026-08-16T09:57:00Z"})
			}
		}
	}
	return policy, profile, NetworkSnapshot{
		Format: NetworkSnapshotFormat, ObservedAt: time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		TargetClusterUID: policy.TargetClusterUID, IntentRevision: policy.IntentRevision,
		EnablementRevision: policy.EnablementRevision, HCP: hcp, HRPCount: 1, HRP: hrp,
		Nodes: nodes, Components: components, AgentPods: pods,
		Probe: NetworkProbe{ResponseTimestamp: "2026-08-16T09:59:00Z", ProbeIntervalMilliseconds: 96566, Paths: paths},
	}
}
