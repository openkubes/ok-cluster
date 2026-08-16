package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestLoadPlatformProfileFileBindsCanonicalMembership(t *testing.T) {
	root := t.TempDir()
	profile := runnerPlatformProfile()
	digest, err := observation.PlatformProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "platform-profile.json")
	writePlatformJSON(t, path, profile)
	config := PlatformProfileFileConfig{
		Path: path, ExpectedProfileDigest: digest, ExpectedIntentRevision: profile.IntentRevision,
		ExpectedPlatformRevision: profile.PlatformRevision, ExpectedExecutionFixture: profile.ExecutionFixture,
		ExpectedTargetClusterUID: profile.TargetClusterUID,
	}
	loaded, err := LoadPlatformProfileFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Digest != digest || loaded.Profile.TargetClusterUID != profile.TargetClusterUID {
		t.Fatalf("loaded Platform profile differs: %#v", loaded)
	}
	profile.RequiredApplications[0], profile.RequiredApplications[2] = profile.RequiredApplications[2], profile.RequiredApplications[0]
	writePlatformJSON(t, path, profile)
	reordered, err := LoadPlatformProfileFile(config)
	if err != nil || reordered.Digest != digest {
		t.Fatalf("equivalent Application membership changed identity: %#v %v", reordered, err)
	}
}

func TestLoadPlatformProfileFileRejectsMalformedOrUnboundInput(t *testing.T) {
	root := t.TempDir()
	profile := runnerPlatformProfile()
	digest, _ := observation.PlatformProfileDigest(profile)
	validRaw, _ := json.Marshal(profile)
	base := PlatformProfileFileConfig{
		ExpectedProfileDigest: digest, ExpectedIntentRevision: profile.IntentRevision,
		ExpectedPlatformRevision: profile.PlatformRevision, ExpectedExecutionFixture: profile.ExecutionFixture,
		ExpectedTargetClusterUID: profile.TargetClusterUID,
	}
	for name, raw := range map[string][]byte{
		"unknown field":   append(validRaw[:len(validRaw)-1], []byte(`,"extra":true}`)...),
		"duplicate field": []byte(strings.Replace(string(validRaw), `"format":"`+observation.PlatformProfileFormat+`"`, `"format":"`+observation.PlatformProfileFormat+`","format":"`+observation.PlatformProfileFormat+`"`, 1)),
		"trailing value":  append(append([]byte(nil), validRaw...), []byte(` {}`)...),
		"oversized":       []byte(`{"format":"` + strings.Repeat("x", maximumPlatformProfileBytes) + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			config := base
			config.Path = path
			if _, err := LoadPlatformProfileFile(config); err == nil || strings.Contains(err.Error(), root) {
				t.Fatalf("unsafe Platform profile accepted or disclosed path: %v", err)
			}
		})
	}
	path := filepath.Join(root, "valid.json")
	writePlatformJSON(t, path, profile)
	base.Path = path
	for name, mutate := range map[string]func(*PlatformProfileFileConfig){
		"wrong digest":  func(config *PlatformProfileFileConfig) { config.ExpectedProfileDigest = digestOf("9") },
		"wrong R":       func(config *PlatformProfileFileConfig) { config.ExpectedIntentRevision = digestOf("9") },
		"wrong P":       func(config *PlatformProfileFileConfig) { config.ExpectedPlatformRevision = digestOf("9") },
		"wrong fixture": func(config *PlatformProfileFileConfig) { config.ExpectedExecutionFixture = digestOf("9") },
		"wrong target":  func(config *PlatformProfileFileConfig) { config.ExpectedTargetClusterUID = "other-cluster-uid" },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := LoadPlatformProfileFile(config); err == nil || strings.Contains(err.Error(), root) {
				t.Fatalf("unbound Platform profile accepted or disclosed path: %v", err)
			}
		})
	}
}

func TestLoadPlatformCapabilityFileProducesImmutableSource(t *testing.T) {
	root := t.TempDir()
	state := runnerPlatformCapability(t)
	path := filepath.Join(root, "platform-capability.json")
	writePlatformJSON(t, path, state)
	config := PlatformCapabilityFileConfig{
		Path: path, ExpectedEvidenceDigest: state.EvidenceDigest, ExpectedIntentRevision: state.IntentRevision,
		ExpectedPlatformRevision: state.PlatformRevision, ExpectedExecutionFixture: state.ExecutionFixture, ExpectedTargetClusterUID: state.TargetClusterUID,
		ExpectedContractDigest: state.ContractDigest, ExpectedExecutableDigest: state.ExecutableDigest,
	}
	loaded, err := LoadPlatformCapabilityFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.EvidenceDigest() != state.EvidenceDigest {
		t.Fatal("loaded capability digest differs")
	}
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	retained, err := loaded.Capability(context.Background())
	if err != nil || retained != state {
		t.Fatalf("loaded capability retained path dependency: %#v %v", retained, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := loaded.Capability(cancelled); err == nil {
		t.Fatal("cancelled capability read was accepted")
	}
}

func TestLoadPlatformCapabilityFileRejectsTamperingAndBindingChanges(t *testing.T) {
	root := t.TempDir()
	state := runnerPlatformCapability(t)
	path := filepath.Join(root, "platform-capability.json")
	writePlatformJSON(t, path, state)
	base := PlatformCapabilityFileConfig{
		Path: path, ExpectedEvidenceDigest: state.EvidenceDigest, ExpectedIntentRevision: state.IntentRevision,
		ExpectedPlatformRevision: state.PlatformRevision, ExpectedExecutionFixture: state.ExecutionFixture, ExpectedTargetClusterUID: state.TargetClusterUID,
		ExpectedContractDigest: state.ContractDigest, ExpectedExecutableDigest: state.ExecutableDigest,
	}
	for name, mutate := range map[string]func(*PlatformCapabilityFileConfig){
		"wrong evidence":   func(config *PlatformCapabilityFileConfig) { config.ExpectedEvidenceDigest = digestOf("9") },
		"wrong R":          func(config *PlatformCapabilityFileConfig) { config.ExpectedIntentRevision = digestOf("9") },
		"wrong P":          func(config *PlatformCapabilityFileConfig) { config.ExpectedPlatformRevision = digestOf("9") },
		"wrong fixture":    func(config *PlatformCapabilityFileConfig) { config.ExpectedExecutionFixture = digestOf("9") },
		"wrong target":     func(config *PlatformCapabilityFileConfig) { config.ExpectedTargetClusterUID = "other-cluster-uid" },
		"wrong contract":   func(config *PlatformCapabilityFileConfig) { config.ExpectedContractDigest = digestOf("9") },
		"wrong executable": func(config *PlatformCapabilityFileConfig) { config.ExpectedExecutableDigest = digestOf("9") },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := LoadPlatformCapabilityFile(config); err == nil || strings.Contains(err.Error(), root) {
				t.Fatalf("unbound capability accepted or disclosed path: %v", err)
			}
		})
	}
	state.Passed = false
	writePlatformJSON(t, path, state)
	if _, err := LoadPlatformCapabilityFile(base); err == nil {
		t.Fatal("tampered capability retained the old semantic digest")
	}
}

func TestLoadPlatformCapabilityFileRejectsMalformedInput(t *testing.T) {
	root := t.TempDir()
	state := runnerPlatformCapability(t)
	validRaw, _ := json.Marshal(state)
	base := PlatformCapabilityFileConfig{
		ExpectedEvidenceDigest: state.EvidenceDigest, ExpectedIntentRevision: state.IntentRevision,
		ExpectedPlatformRevision: state.PlatformRevision, ExpectedExecutionFixture: state.ExecutionFixture, ExpectedTargetClusterUID: state.TargetClusterUID,
		ExpectedContractDigest: state.ContractDigest, ExpectedExecutableDigest: state.ExecutableDigest,
	}
	for name, raw := range map[string][]byte{
		"unknown field":   append(validRaw[:len(validRaw)-1], []byte(`,"extra":true}`)...),
		"duplicate field": []byte(strings.Replace(string(validRaw), `"format":"`+observation.PlatformCapabilityFormat+`"`, `"format":"`+observation.PlatformCapabilityFormat+`","format":"`+observation.PlatformCapabilityFormat+`"`, 1)),
		"trailing value":  append(append([]byte(nil), validRaw...), []byte(` {}`)...),
		"oversized":       []byte(`{"format":"` + strings.Repeat("x", maximumPlatformCapabilityBytes) + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			config := base
			config.Path = path
			if _, err := LoadPlatformCapabilityFile(config); err == nil || strings.Contains(err.Error(), root) {
				t.Fatalf("unsafe capability input accepted or disclosed path: %v", err)
			}
		})
	}
}

func runnerPlatformProfile() observation.PlatformProfile {
	return observation.PlatformProfile{
		Format: observation.PlatformProfileFormat, IntentRevision: digestOf("a"), PlatformRevision: digestOf("b"), ExecutionFixture: digestOf("c"),
		TargetClusterUID: "cluster-uid-disposable-ok141", ArgoNamespace: "argocd", RegistrationName: "disposable-ok141",
		RequiredApplications: []observation.PlatformApplicationExpectation{
			{Name: "disposable-ok141-observability-core", SpecDigest: digestOf("1")},
			{Name: "disposable-ok141-observability-alerting", SpecDigest: digestOf("2")},
			{Name: "disposable-ok141-observability-dashboards", SpecDigest: digestOf("3")},
		},
		CapabilityContractDigest: digestOf("4"), CapabilityExecutableDigest: digestOf("5"), MaximumCapabilityAgeSeconds: 3600,
	}
}

func runnerPlatformCapability(t *testing.T) observation.PlatformCapabilityState {
	t.Helper()
	profile := runnerPlatformProfile()
	state := observation.PlatformCapabilityState{
		Format: observation.PlatformCapabilityFormat, ObservedAt: "2026-08-16T09:55:00Z", TargetClusterUID: profile.TargetClusterUID,
		IntentRevision: profile.IntentRevision, PlatformRevision: profile.PlatformRevision, ExecutionFixture: profile.ExecutionFixture,
		ContractDigest: profile.CapabilityContractDigest, ExecutableDigest: profile.CapabilityExecutableDigest, Passed: true,
	}
	digest, err := observation.PlatformCapabilityDigest(state)
	if err != nil {
		t.Fatal(err)
	}
	state.EvidenceDigest = digest
	return state
}

func writePlatformJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func digestOf(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}
