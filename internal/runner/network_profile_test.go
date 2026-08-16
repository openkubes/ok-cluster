package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestLoadNetworkProfileFileBindsCanonicalIdentity(t *testing.T) {
	root := t.TempDir()
	profile := runnerNetworkProfile()
	digest, err := observation.NetworkProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "network-profile.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	config := NetworkProfileFileConfig{
		Path: path, ExpectedProfileDigest: digest,
		ExpectedIntentRevision: profile.IntentRevision, ExpectedEnablementRevision: profile.EnablementRevision,
	}
	loaded, err := LoadNetworkProfileFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Profile != profile || loaded.Digest != digest {
		t.Fatalf("loaded profile differs: %#v", loaded)
	}

	var reordered map[string]any
	if err := json.Unmarshal(raw, &reordered); err != nil {
		t.Fatal(err)
	}
	reorderedRaw, err := json.Marshal(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, reorderedRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	semanticallySame, err := LoadNetworkProfileFile(config)
	if err != nil || semanticallySame.Digest != digest {
		t.Fatalf("semantically identical JSON changed identity: %#v %v", semanticallySame, err)
	}
}

func TestLoadNetworkProfileFileRejectsUnboundOrMalformedInput(t *testing.T) {
	root := t.TempDir()
	profile := runnerNetworkProfile()
	digest, _ := observation.NetworkProfileDigest(profile)
	validRaw, _ := json.Marshal(profile)
	base := NetworkProfileFileConfig{
		ExpectedProfileDigest: digest, ExpectedIntentRevision: profile.IntentRevision,
		ExpectedEnablementRevision: profile.EnablementRevision,
	}
	tests := map[string][]byte{
		"unknown field":   append(validRaw[:len(validRaw)-1], []byte(`,"extra":true}`)...),
		"duplicate field": []byte(strings.Replace(string(validRaw), `"format":"`+observation.NetworkProfileFormat+`"`, `"format":"`+observation.NetworkProfileFormat+`","format":"`+observation.NetworkProfileFormat+`"`, 1)),
		"trailing value":  append(append([]byte(nil), validRaw...), []byte(` {}`)...),
		"oversized":       []byte(`{"format":"` + strings.Repeat("x", maximumNetworkProfileBytes) + `"}`),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			config := base
			config.Path = path
			if _, err := LoadNetworkProfileFile(config); err == nil || strings.Contains(err.Error(), root) {
				t.Fatalf("unsafe profile accepted or disclosed path: %v", err)
			}
		})
	}
}

func TestLoadNetworkProfileFileRejectsIdentityOrSemanticChanges(t *testing.T) {
	root := t.TempDir()
	profile := runnerNetworkProfile()
	digest, _ := observation.NetworkProfileDigest(profile)
	path := filepath.Join(root, "network-profile.json")
	write := func(value observation.NetworkProfile) {
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(profile)
	base := NetworkProfileFileConfig{
		Path: path, ExpectedProfileDigest: digest, ExpectedIntentRevision: profile.IntentRevision,
		ExpectedEnablementRevision: profile.EnablementRevision,
	}
	for name, mutate := range map[string]func(*NetworkProfileFileConfig){
		"malformed digest": func(config *NetworkProfileFileConfig) { config.ExpectedProfileDigest = "sha256:no" },
		"wrong digest": func(config *NetworkProfileFileConfig) {
			config.ExpectedProfileDigest = "sha256:" + strings.Repeat("9", 64)
		},
		"wrong R": func(config *NetworkProfileFileConfig) {
			config.ExpectedIntentRevision = "sha256:" + strings.Repeat("9", 64)
		},
		"wrong E": func(config *NetworkProfileFileConfig) {
			config.ExpectedEnablementRevision = "sha256:" + strings.Repeat("9", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := LoadNetworkProfileFile(config); err == nil || strings.Contains(err.Error(), root) {
				t.Fatalf("unbound profile accepted or disclosed path: %v", err)
			}
		})
	}

	changed := profile
	changed.CacheExposureSeconds++
	write(changed)
	if _, err := LoadNetworkProfileFile(base); err == nil {
		t.Fatal("semantic profile change retained the old binding")
	}
}

func runnerNetworkProfile() observation.NetworkProfile {
	return observation.NetworkProfile{
		Format:         observation.NetworkProfileFormat,
		IntentRevision: "sha256:" + strings.Repeat("a", 64), EnablementRevision: "sha256:" + strings.Repeat("b", 64),
		ExpectedNodeCount: 2, ExpectedHCPSpecDigest: "sha256:" + strings.Repeat("c", 64), ExpectedHRPSpecDigest: "sha256:" + strings.Repeat("d", 64),
		ExpectedImages: observation.NetworkImages{
			CiliumAgent:    "registry.example/cilium@sha256:" + strings.Repeat("1", 64),
			CiliumEnvoy:    "registry.example/envoy@sha256:" + strings.Repeat("2", 64),
			CiliumOperator: "registry.example/operator@sha256:" + strings.Repeat("3", 64),
		},
		MinimumProbeFreshnessSeconds: 120, MaximumProbeIntervalSeconds: 60, CacheExposureSeconds: 30,
	}
}
