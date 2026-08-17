package runner

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildTargetAccessStageLaunchMaterialSealsPrivateComponents(t *testing.T) {
	config, tokens := targetAccessStageLaunchMaterialConfig(t)
	material, err := BuildTargetAccessStageLaunchMaterial(config)
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
	again, err := BuildTargetAccessStageLaunchMaterial(config)
	if err != nil {
		t.Fatal(err)
	}
	againReceipt, _ := again.Receipt()
	if receipt.Format != TargetAccessStageLaunchMaterialFormat || receipt.State != "VERIFIED" || receipt.StageID != "target-access" || receipt.Authority != "ok-shared" || receipt.TargetAccessPackageDigest != candidate.TargetAccessPackageDigest || receipt.CandidateDigest != candidate.CandidateDigest || receipt.ValidUntil != candidate.ValidUntil || receipt.MutationAllowed || receipt.CandidateDigest != againReceipt.CandidateDigest {
		t.Fatalf("unexpected target-access launch material: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append(tokens, material.packaged.raw, material.credentials.objects[0].raw, material.credentials.objects[1].raw, material.runtime.raw, []byte(config.Candidate.AuthorityEndpoint), []byte(config.Candidate.InstallerTokenDigest)) {
		if bytes.Contains(public, forbidden) {
			t.Fatal("target-access launch material receipt exposed private source content")
		}
	}
	changed := material
	changed.receipt.CandidateDigest = digest.SHA256([]byte("foreign"))
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed target-access launch material identity accepted")
	}
	changed = material
	changed.credentials.objects[1].raw = append(changed.credentials.objects[1].raw, '\n')
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed private workload credential accepted")
	}
}

func TestBuildTargetAccessStageLaunchMaterialFailsClosed(t *testing.T) {
	valid, _ := targetAccessStageLaunchMaterialConfig(t)
	for name, mutate := range map[string]func(*TargetAccessStageLaunchMaterialConfig){
		"wrong runtime digest": func(config *TargetAccessStageLaunchMaterialConfig) {
			config.RuntimeManifestDigest = digest.SHA256([]byte("foreign"))
		},
		"foreign workload token": func(config *TargetAccessStageLaunchMaterialConfig) {
			config.WorkloadWriter.AuthorityIdentity = digest.SHA256([]byte("foreign"))
		},
		"expired candidate": func(config *TargetAccessStageLaunchMaterialConfig) {
			config.Candidate.PreparedAt = config.MaterializationTime.Add(16 * time.Minute)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := BuildTargetAccessStageLaunchMaterial(config); err == nil {
				t.Fatal("invalid target-access launch material accepted")
			}
		})
	}
	if _, err := (VerifiedTargetAccessStageLaunchMaterial{}).Receipt(); err == nil {
		t.Fatal("unverified target-access launch material receipt exposed")
	}
}

func targetAccessStageLaunchMaterialConfig(t *testing.T) (TargetAccessStageLaunchMaterialConfig, [][]byte) {
	t.Helper()
	credentialConfig, packageConfig, tokens := targetAccessCredentialInputs(t)
	manifest := submissionStageRuntimeManifest(t)
	return TargetAccessStageLaunchMaterialConfig{
		Package: packageConfig, MaterializationTime: credentialConfig.MaterializationTime,
		LedgerWriter: credentialConfig.LedgerWriter, WorkloadWriter: credentialConfig.WorkloadWriter,
		RuntimeManifest: manifest, RuntimeManifestDigest: digest.SHA256(manifest),
		Candidate: targetAccessLaunchCandidateConfig(),
	}, tokens
}
