package runner

import (
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPrepareAggregateEvidenceStageInstallationRecoversExactObjects(t *testing.T) {
	stage, err := BuildAggregateEvidenceStagePackage(aggregateEvidenceStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	plan, objects, err := prepareAggregateEvidenceStageInstallation(stage)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 || len(plan.Creates) != 3 {
		t.Fatalf("unexpected aggregate installation material count: %d %d", len(objects), len(plan.Creates))
	}
	for index, object := range objects {
		if object.plan != plan.Creates[index] || digest.SHA256(object.raw) != plan.Creates[index].ObjectDigest {
			t.Fatalf("aggregate installation object %d differs", index)
		}
	}
	objects[0].raw[0] = 'x'
	_, again, err := prepareAggregateEvidenceStageInstallation(stage)
	if err != nil || again[0].raw[0] == 'x' {
		t.Fatal("caller mutated retained aggregate installation material")
	}
}

func TestPrepareAggregateEvidenceStageCredentialInstallationRecoversFourSecrets(t *testing.T) {
	config, tokens := aggregateEvidenceCredentialConfig(t)
	credentials, err := BuildAggregateEvidenceStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, objects, err := prepareAggregateEvidenceStageCredentialInstallation(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 4 || len(receipt.Credentials) != 4 {
		t.Fatalf("unexpected aggregate credential material count: %d %d", len(objects), len(receipt.Credentials))
	}
	for index, object := range objects {
		if object.order != index+4 || object.role != receipt.Credentials[index].Role || object.authority != receipt.Credentials[index].Authority || object.name != receipt.Credentials[index].Name || object.objectDigest != receipt.Credentials[index].ObjectDigest || digest.SHA256(object.raw) != object.objectDigest || string(object.token) != string(tokens[index]) {
			t.Fatalf("aggregate credential installation object %d differs: %#v", index, object)
		}
		var secret map[string]any
		if err := json.Unmarshal(object.raw, &secret); err != nil {
			t.Fatal(err)
		}
		if len(secret["data"].(map[string]any)) != 2 {
			t.Fatalf("aggregate credential %d contains unexpected private data", index)
		}
	}
	objects[3].raw[0] = 'x'
	_, again, err := prepareAggregateEvidenceStageCredentialInstallation(credentials)
	if err != nil || again[3].raw[0] == 'x' {
		t.Fatal("caller mutated retained private aggregate credentials")
	}
}

func TestPrepareAggregateEvidenceStageCredentialInstallationRejectsTampering(t *testing.T) {
	config, _ := aggregateEvidenceCredentialConfig(t)
	credentials, err := BuildAggregateEvidenceStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	credentials.objects[2].raw = append(credentials.objects[2].raw, '\n')
	if _, _, err := prepareAggregateEvidenceStageCredentialInstallation(credentials); err == nil {
		t.Fatal("changed aggregate evidence credential was accepted")
	}
	if _, _, err := prepareAggregateEvidenceStageCredentialInstallation(VerifiedAggregateEvidenceStageCredentialPackage{}); err == nil {
		t.Fatal("unverified aggregate evidence credentials were accepted")
	}
}
