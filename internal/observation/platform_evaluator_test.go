package observation

import (
	"strings"
	"testing"
)

func TestEvaluatePlatformSnapshotProducesCurrentEvidence(t *testing.T) {
	policy, profile, snapshot := validPlatformFixture(t)
	evidence, err := EvaluatePlatformSnapshot(policy, profile, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Type != "PlatformReady" || evidence.Source != "BoundedPlatformEvaluator" || evidence.Status != "True" || evidence.Reason != "PlatformReady" || evidence.ObservedRevision != policy.PlatformRevision || !validDigest(evidence.EvidenceDigest) {
		t.Fatalf("unexpected platform evidence: %#v", evidence)
	}
	bundle := completeBundle(policy)
	bundle.Evidence[3] = evidence
	result, err := Evaluate(policy, bundle)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "True" {
		t.Fatalf("platform evidence did not compose: %#v", receipt)
	}
}

func TestEvaluatePlatformSnapshotBindsProfileAndCapabilityIdentity(t *testing.T) {
	policy, profile, snapshot := validPlatformFixture(t)
	first, err := EvaluatePlatformSnapshot(policy, profile, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	profile.MaximumCapabilityAgeSeconds++
	second, err := EvaluatePlatformSnapshot(policy, profile, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if first.EvidenceDigest == second.EvidenceDigest || first.SourceUID == second.SourceUID {
		t.Fatal("platform profile semantic change was not bound into evidence")
	}
	snapshot.Capability.Passed = false
	if _, err := EvaluatePlatformSnapshot(policy, profile, snapshot); err == nil {
		t.Fatal("tampered capability assertion was accepted without a matching digest")
	}
}

func TestPlatformProfileDigestTreatsApplicationMembershipAsASet(t *testing.T) {
	_, profile, _ := validPlatformFixture(t)
	first, err := PlatformProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	profile.RequiredApplications[0], profile.RequiredApplications[2] = profile.RequiredApplications[2], profile.RequiredApplications[0]
	second, err := PlatformProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("membership ordering changed semantic profile identity: %s != %s", first, second)
	}
}

func TestEvaluatePlatformSnapshotFailsClosed(t *testing.T) {
	tests := map[string]struct {
		mutate func(*PlatformProfile, *PlatformSnapshot)
		status string
		reason string
	}{
		"foreign target": {
			mutate: func(_ *PlatformProfile, snapshot *PlatformSnapshot) { snapshot.TargetClusterUID = "other-cluster-uid" },
			status: "Unknown", reason: "RevisionCorrelationUnproven",
		},
		"wrong P carrier": {
			mutate: func(_ *PlatformProfile, snapshot *PlatformSnapshot) {
				snapshot.Applications[0].PlatformRevision = "sha256:" + strings.Repeat("f", 64)
			},
			status: "Unknown", reason: "RevisionCorrelationUnproven",
		},
		"wrong fixture carrier": {
			mutate: func(_ *PlatformProfile, snapshot *PlatformSnapshot) {
				snapshot.Applications[0].ExecutionFixture = "sha256:" + strings.Repeat("f", 64)
			},
			status: "Unknown", reason: "RevisionCorrelationUnproven",
		},
		"application spec drift": {
			mutate: func(_ *PlatformProfile, snapshot *PlatformSnapshot) {
				snapshot.Applications[0].SpecDigest = "sha256:" + strings.Repeat("f", 64)
			},
			status: "False", reason: "PlatformApplicationIdentityMismatch",
		},
		"applied revision pending": {
			mutate: func(_ *PlatformProfile, snapshot *PlatformSnapshot) {
				snapshot.Applications[0].AppliedSourceRevision = strings.Repeat("f", 40)
			},
			status: "Unknown", reason: "PlatformConvergencePending",
		},
		"out of sync": {
			mutate: func(_ *PlatformProfile, snapshot *PlatformSnapshot) {
				snapshot.Applications[0].SyncStatus = "OutOfSync"
			},
			status: "Unknown", reason: "PlatformConvergencePending",
		},
		"degraded": {
			mutate: func(_ *PlatformProfile, snapshot *PlatformSnapshot) {
				snapshot.Applications[0].HealthStatus = "Degraded"
			},
			status: "False", reason: "PlatformHealthFailed",
		},
		"application missing": {
			mutate: func(_ *PlatformProfile, snapshot *PlatformSnapshot) {
				snapshot.Applications = snapshot.Applications[:1]
			},
			status: "Unknown", reason: "PlatformApplicationMissing",
		},
		"capability stale": {
			mutate: func(_ *PlatformProfile, snapshot *PlatformSnapshot) {
				snapshot.Capability.ObservedAt = "2026-08-16T08:00:00Z"
				rebindPlatformCapability(t, snapshot)
			},
			status: "Unknown", reason: "PlatformCapabilityStale",
		},
		"capability from other fixture": {
			mutate: func(_ *PlatformProfile, snapshot *PlatformSnapshot) {
				snapshot.Capability.ExecutionFixture = "sha256:" + strings.Repeat("f", 64)
				rebindPlatformCapability(t, snapshot)
			},
			status: "Unknown", reason: "RevisionCorrelationUnproven",
		},
		"capability failed": {
			mutate: func(_ *PlatformProfile, snapshot *PlatformSnapshot) {
				snapshot.Capability.Passed = false
				rebindPlatformCapability(t, snapshot)
			},
			status: "False", reason: "PlatformCapabilityFailed",
		},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			policy, profile, snapshot := validPlatformFixture(t)
			testCase.mutate(&profile, &snapshot)
			evidence, err := EvaluatePlatformSnapshot(policy, profile, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != testCase.status || evidence.Reason != testCase.reason || evidence.Status == "True" {
				t.Fatalf("unsafe platform result: %#v", evidence)
			}
		})
	}
}

func TestValidatePlatformProfileRejectsMutableOrAmbiguousInputs(t *testing.T) {
	_, profile, _ := validPlatformFixture(t)
	for name, mutate := range map[string]func(*PlatformProfile){
		"duplicate application":    func(value *PlatformProfile) { value.RequiredApplications[1].Name = value.RequiredApplications[0].Name },
		"invalid spec digest":      func(value *PlatformProfile) { value.RequiredApplications[0].SpecDigest = "sha256:no" },
		"unbounded capability age": func(value *PlatformProfile) { value.MaximumCapabilityAgeSeconds = 86401 },
		"missing fixture":          func(value *PlatformProfile) { value.ExecutionFixture = "" },
		"wrong target scheme":      func(value *PlatformProfile) { value.TargetIdentityScheme = "name/v1" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := profile
			candidate.RequiredApplications = append([]PlatformApplicationExpectation(nil), profile.RequiredApplications...)
			mutate(&candidate)
			if err := ValidatePlatformProfile(candidate); err == nil {
				t.Fatal("unsafe platform profile accepted")
			}
		})
	}
}

func validPlatformFixture(t *testing.T) (Policy, PlatformProfile, PlatformSnapshot) {
	t.Helper()
	policy := Policy{
		Format: PolicyFormat, IntentRevision: "sha256:" + strings.Repeat("a", 64),
		EnablementRevision: "sha256:" + strings.Repeat("b", 64), PlatformRevision: "sha256:" + strings.Repeat("c", 64),
		TargetClusterUID: "cluster-uid-disposable-ok141",
		Required:         []string{"InfrastructureReady", "ControlPlaneAvailable", "NetworkReady", "PlatformReady"},
	}
	fixture := "sha256:" + strings.Repeat("d", 64)
	profile := PlatformProfile{
		Format: PlatformProfileFormat, IntentRevision: policy.IntentRevision, PlatformRevision: policy.PlatformRevision,
		ExecutionFixture: fixture, TargetIdentityScheme: "capi-cluster-uid/v1", ArgoNamespace: "argocd", RegistrationName: "disposable-ok141",
		RequiredApplications: []PlatformApplicationExpectation{
			{Name: "disposable-ok141-observability-core", SpecDigest: "sha256:" + strings.Repeat("1", 64)},
			{Name: "disposable-ok141-observability-alerting", SpecDigest: "sha256:" + strings.Repeat("2", 64)},
			{Name: "disposable-ok141-observability-dashboards", SpecDigest: "sha256:" + strings.Repeat("3", 64)},
		},
		CapabilityContractDigest: "sha256:" + strings.Repeat("4", 64), CapabilityExecutableDigest: "sha256:" + strings.Repeat("5", 64),
		MaximumCapabilityAgeSeconds: 3600,
	}
	commit := strings.Repeat("6", 40)
	applications := make([]PlatformApplicationState, 0, len(profile.RequiredApplications))
	for index, expected := range profile.RequiredApplications {
		applications = append(applications, PlatformApplicationState{
			Name: expected.Name, UID: "application-uid-" + string(rune('a'+index)), ResourceVersion: "17",
			IntentRevision: policy.IntentRevision, PlatformRevision: policy.PlatformRevision, ExecutionFixture: fixture,
			SpecDigest: expected.SpecDigest, DesiredSourceRevision: commit, AppliedSourceRevision: commit,
			SyncStatus: "Synced", HealthStatus: "Healthy",
		})
	}
	snapshot := PlatformSnapshot{
		Format: PlatformSnapshotFormat, ObservedAt: "2026-08-16T10:00:00Z", TargetClusterUID: policy.TargetClusterUID,
		Applications: applications,
		Capability: PlatformCapabilityState{
			Format: PlatformCapabilityFormat, ObservedAt: "2026-08-16T09:55:00Z", TargetClusterUID: policy.TargetClusterUID,
			IntentRevision: policy.IntentRevision, PlatformRevision: policy.PlatformRevision, ExecutionFixture: fixture,
			ContractDigest: profile.CapabilityContractDigest, ExecutableDigest: profile.CapabilityExecutableDigest, Passed: true,
		},
	}
	rebindPlatformCapability(t, &snapshot)
	return policy, profile, snapshot
}

func rebindPlatformCapability(t *testing.T, snapshot *PlatformSnapshot) {
	t.Helper()
	digest, err := PlatformCapabilityDigest(snapshot.Capability)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Capability.EvidenceDigest = digest
}
