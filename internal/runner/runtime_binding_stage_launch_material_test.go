package runner

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildRuntimeBindingStageLaunchMaterialSealsPrivateComponents(t *testing.T) {
	config, tokens := runtimeBindingStageLaunchMaterialConfig(t)
	material, err := BuildRuntimeBindingStageLaunchMaterial(config)
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
	if receipt.Format != RuntimeBindingStageLaunchMaterialFormat || receipt.State != "VERIFIED" || receipt.StageID != "runtime-binding" || receipt.Authority != "ok-mgmt" || receipt.StagePackageDigest != candidate.StagePackageDigest || receipt.CandidateDigest != candidate.CandidateDigest || receipt.ValidUntil != candidate.ValidUntil || receipt.MutationAllowed {
		t.Fatalf("unexpected runtime binding launch material: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append(tokens, material.packaged.raw, material.credentials.objects[0].raw, material.credentials.objects[1].raw, material.credentials.objects[2].raw, material.runtime.raw, []byte(config.Candidate.AuthorityEndpoint), []byte(config.Candidate.InstallerTokenDigest)) {
		if bytes.Contains(public, forbidden) {
			t.Fatal("runtime binding launch material receipt exposed private source content")
		}
	}
	changed := material
	changed.receipt.CandidateDigest = digest.SHA256([]byte("foreign"))
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed runtime binding launch material identity accepted")
	}
	changed = material
	changed.credentials.objects[2].raw = append(changed.credentials.objects[2].raw, '\n')
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed private workload credential accepted")
	}
}

func TestBuildRuntimeBindingStageLaunchMaterialFailsClosed(t *testing.T) {
	valid, _ := runtimeBindingStageLaunchMaterialConfig(t)
	for name, mutate := range map[string]func(*RuntimeBindingStageLaunchMaterialConfig){
		"wrong runtime digest": func(config *RuntimeBindingStageLaunchMaterialConfig) {
			config.RuntimeManifestDigest = digest.SHA256([]byte("foreign"))
		},
		"foreign workload token": func(config *RuntimeBindingStageLaunchMaterialConfig) {
			config.WorkloadObserver.AuthorityIdentity = digest.SHA256([]byte("foreign"))
		},
		"expired candidate": func(config *RuntimeBindingStageLaunchMaterialConfig) {
			config.Candidate.PreparedAt = config.MaterializationTime.Add(16 * time.Minute)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := BuildRuntimeBindingStageLaunchMaterial(config); err == nil {
				t.Fatal("invalid runtime binding launch material accepted")
			}
		})
	}
	if _, err := (VerifiedRuntimeBindingStageLaunchMaterial{}).Receipt(); err == nil {
		t.Fatal("unverified runtime binding launch material receipt exposed")
	}
}

func runtimeBindingStageLaunchMaterialConfig(t *testing.T) (RuntimeBindingStageLaunchMaterialConfig, [][]byte) {
	t.Helper()
	credentialConfig, packageConfig, tokens := runtimeBindingCredentialInputs(t)
	manifest := submissionStageRuntimeManifest(t)
	return RuntimeBindingStageLaunchMaterialConfig{
		Package: packageConfig, MaterializationTime: credentialConfig.MaterializationTime,
		LedgerWriter: credentialConfig.LedgerWriter, PersistenceWriter: credentialConfig.PersistenceWriter,
		WorkloadObserver: credentialConfig.WorkloadObserver,
		RuntimeManifest:  manifest, RuntimeManifestDigest: digest.SHA256(manifest),
		Candidate: submissionStageLaunchCandidateConfig(),
	}, tokens
}
