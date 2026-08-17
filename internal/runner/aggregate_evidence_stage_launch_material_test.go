package runner

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildAggregateEvidenceStageLaunchMaterialSealsAllPrivateComponents(t *testing.T) {
	config, tokens := aggregateEvidenceStageLaunchMaterialConfig(t)
	material, err := BuildAggregateEvidenceStageLaunchMaterial(config)
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
	if receipt.Format != AggregateEvidenceStageLaunchMaterialFormat || receipt.State != "VERIFIED" || receipt.StageID != "aggregate-evidence" || receipt.Authority != "ok-mgmt" || receipt.EvidencePackageDigest != candidate.EvidencePackageDigest || receipt.CredentialPackageDigest != candidate.CredentialPackageDigest || receipt.PrivateInputPackageDigest != candidate.PrivateInputPackageDigest || receipt.RuntimeManifestDigest != candidate.RuntimeManifestDigest || receipt.LaunchPlanDigest != candidate.LaunchPlanDigest || receipt.CandidateDigest != candidate.CandidateDigest || receipt.ValidUntil != candidate.ValidUntil || receipt.MutationAllowed {
		t.Fatalf("unexpected aggregate evidence launch material: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append(tokens,
		material.packaged.raw,
		material.credentials.objects[0].raw, material.credentials.objects[1].raw,
		material.credentials.objects[2].raw, material.credentials.objects[3].raw,
		material.privateInputs.objects[0].raw, material.privateInputs.objects[1].raw,
		material.runtime.raw,
		[]byte(config.Candidate.AuthorityEndpoint), []byte(config.Candidate.InstallerTokenDigest),
	) {
		if bytes.Contains(public, forbidden) {
			t.Fatal("aggregate evidence launch material receipt exposed private source content")
		}
	}
	changed := material
	changed.receipt.CandidateDigest = digest.SHA256([]byte("foreign"))
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed aggregate evidence launch material identity accepted")
	}
	changed = material
	changed.privateInputs.objects[1].raw = append(changed.privateInputs.objects[1].raw, '\n')
	if _, err := changed.Receipt(); err == nil {
		t.Fatal("changed private capability input accepted")
	}
}

func TestBuildAggregateEvidenceStageLaunchMaterialFailsClosed(t *testing.T) {
	valid, _ := aggregateEvidenceStageLaunchMaterialConfig(t)
	for name, mutate := range map[string]func(*AggregateEvidenceStageLaunchMaterialConfig){
		"wrong runtime digest": func(config *AggregateEvidenceStageLaunchMaterialConfig) {
			config.RuntimeManifestDigest = digest.SHA256([]byte("foreign"))
		},
		"foreign Argo observer": func(config *AggregateEvidenceStageLaunchMaterialConfig) {
			config.ArgoObserver.AuthorityIdentity = "ok-mgmt"
		},
		"expired candidate": func(config *AggregateEvidenceStageLaunchMaterialConfig) {
			config.Candidate.PreparedAt = config.MaterializationTime.Add(16 * time.Minute)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := BuildAggregateEvidenceStageLaunchMaterial(config); err == nil {
				t.Fatal("invalid aggregate evidence launch material accepted")
			}
		})
	}
	if _, err := (VerifiedAggregateEvidenceStageLaunchMaterial{}).Receipt(); err == nil {
		t.Fatal("unverified aggregate evidence launch material receipt exposed")
	}
}

func aggregateEvidenceStageLaunchMaterialConfig(t *testing.T) (AggregateEvidenceStageLaunchMaterialConfig, [][]byte) {
	t.Helper()
	packageConfig := aggregateEvidenceStagePackageConfig(t)
	credentialConfig, tokens := aggregateEvidenceCredentialConfigForPackage(t, packageConfig)
	manifest := submissionStageRuntimeManifest(t)
	return AggregateEvidenceStageLaunchMaterialConfig{
		Package: packageConfig, MaterializationTime: credentialConfig.MaterializationTime,
		Ledger: credentialConfig.Ledger, ManagementObserver: credentialConfig.ManagementObserver,
		WorkloadObserver: credentialConfig.WorkloadObserver, ArgoObserver: credentialConfig.ArgoObserver,
		RuntimeManifest: manifest, RuntimeManifestDigest: digest.SHA256(manifest),
		Candidate: submissionStageLaunchCandidateConfig(),
	}, tokens
}
