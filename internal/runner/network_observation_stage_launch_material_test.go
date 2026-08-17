package runner

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildNetworkObservationStageLaunchMaterialSealsPrivateComponents(t *testing.T) {
	config, tokens := networkObservationStageLaunchMaterialConfig(t)
	material, err := BuildNetworkObservationStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := material.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := material.CandidateReceipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != NetworkObservationStageLaunchMaterialFormat || receipt.State != "VERIFIED" || receipt.StageID != "network-observation" || receipt.Authority != "ok-mgmt" || receipt.ObservationPackageDigest != candidate.ObservationPackageDigest || receipt.CandidateDigest != candidate.CandidateDigest || receipt.ValidUntil != candidate.ValidUntil || receipt.MutationAllowed {
		t.Fatalf("unexpected network observation launch material: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append(tokens, material.packaged.raw, material.credentials.objects[0].raw, material.credentials.objects[1].raw, material.credentials.objects[2].raw, material.runtime.raw, []byte(config.Candidate.AuthorityEndpoint), []byte(config.Candidate.InstallerTokenDigest)) {
		if bytes.Contains(public, forbidden) {
			t.Fatal("network launch material receipt exposed private source content")
		}
	}
	changed := material
	changed.receipt.CandidateDigest = digest.SHA256([]byte("foreign"))
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed network launch material identity accepted")
	}
	changed = material
	changed.credentials.objects[2].raw = append(changed.credentials.objects[2].raw, '\n')
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed private workload credential accepted")
	}
}

func TestBuildNetworkObservationStageLaunchMaterialFailsClosed(t *testing.T) {
	valid, _ := networkObservationStageLaunchMaterialConfig(t)
	for name, mutate := range map[string]func(*NetworkObservationStageLaunchMaterialConfig){
		"wrong runtime digest": func(config *NetworkObservationStageLaunchMaterialConfig) {
			config.RuntimeManifestDigest = digest.SHA256([]byte("foreign"))
		},
		"foreign workload token": func(config *NetworkObservationStageLaunchMaterialConfig) {
			config.WorkloadObserver.AuthorityIdentity = digest.SHA256([]byte("foreign"))
		},
		"expired candidate": func(config *NetworkObservationStageLaunchMaterialConfig) {
			config.Candidate.PreparedAt = config.MaterializationTime.Add(16 * time.Minute)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := BuildNetworkObservationStageLaunchMaterial(config); err == nil {
				t.Fatal("invalid network observation launch material accepted")
			}
		})
	}
	if _, err := (VerifiedNetworkObservationStageLaunchMaterial{}).Receipt(); err == nil {
		t.Fatal("unverified network launch material receipt exposed")
	}
}

func networkObservationStageLaunchMaterialConfig(t *testing.T) (NetworkObservationStageLaunchMaterialConfig, [][]byte) {
	t.Helper()
	credentialConfig, packageConfig, tokens := networkObservationCredentialInputs(t)
	manifest := submissionStageRuntimeManifest(t)
	return NetworkObservationStageLaunchMaterialConfig{
		Package: packageConfig, MaterializationTime: credentialConfig.MaterializationTime,
		Ledger: credentialConfig.Ledger, ManagementObserver: credentialConfig.ManagementObserver,
		WorkloadObserver: credentialConfig.WorkloadObserver,
		RuntimeManifest:  manifest, RuntimeManifestDigest: digest.SHA256(manifest),
		Candidate: submissionStageLaunchCandidateConfig(),
	}, tokens
}
