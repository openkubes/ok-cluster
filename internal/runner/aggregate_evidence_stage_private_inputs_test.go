package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildAggregateEvidenceStagePrivateInputPackageSeparatesPolicies(t *testing.T) {
	stage, err := BuildAggregateEvidenceStagePackage(aggregateEvidenceStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	packaged, err := BuildAggregateEvidenceStagePrivateInputPackage(stage)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	stageReceipt, _ := stage.Receipt()
	if receipt.Format != AggregateEvidenceStagePrivateInputPackageFormat || receipt.State != "VERIFIED" || receipt.StageID != "aggregate-evidence" || receipt.EvidencePackageDigest != stageReceipt.PackageDigest || receipt.Authority != "ok-mgmt" || receipt.MutationAllowed || !stageReceiptPrefixDigestPattern.MatchString(receipt.PackageDigest) || len(receipt.Objects) != 2 {
		t.Fatalf("unexpected aggregate private input receipt: %#v", receipt)
	}
	if receipt.Objects[0].Role != "runtime-binding" || receipt.Objects[0].ExistingPolicy != "REQUIRE_EXACT_EXISTING" || receipt.Objects[0].CreatePolicy != "DO_NOT_CREATE" || receipt.Objects[0].ContentDigest != stage.runtimeDigest {
		t.Fatalf("runtime input policy differs: %#v", receipt.Objects[0])
	}
	if receipt.Objects[1].Role != "platform-capability" || receipt.Objects[1].ExistingPolicy != "VERIFY_EXACT_GLOBAL_STATE" || receipt.Objects[1].CreatePolicy != "CREATE_ONLY_AFTER_GLOBAL_ABSENCE" || receipt.Objects[1].ContentDigest != stage.capabilityDigest {
		t.Fatalf("capability input policy differs: %#v", receipt.Objects[1])
	}
	for index, object := range packaged.objects {
		if object.name != receipt.Objects[index].Name || digest.SHA256(object.raw) != receipt.Objects[index].ObjectDigest {
			t.Fatalf("private aggregate object %d differs", index)
		}
	}
	var capabilitySecret map[string]any
	if err := json.Unmarshal(packaged.objects[1].raw, &capabilitySecret); err != nil {
		t.Fatal(err)
	}
	capabilityData := capabilitySecret["data"].(map[string]any)
	capabilityRaw, err := base64.StdEncoding.DecodeString(capabilityData["platform-capability.json"].(string))
	if err != nil || !bytes.Equal(capabilityRaw, stage.capabilityRaw) {
		t.Fatal("private capability Secret payload differs")
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{stage.runtimeMaterialRaw, stage.runtimeReceiptRaw, stage.capabilityRaw, []byte(targetAccessRuntimeUID)} {
		if bytes.Contains(public, forbidden) {
			t.Fatal("aggregate private input receipt exposed private payload")
		}
	}
	receipt.Objects[0].Name = "changed"
	again, err := packaged.Receipt()
	if err != nil || again.Objects[0].Name == "changed" {
		t.Fatal("caller mutated retained aggregate private input receipt")
	}
}

func TestAggregateEvidenceStagePrivateInputsFailClosed(t *testing.T) {
	stage, err := BuildAggregateEvidenceStagePackage(aggregateEvidenceStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*VerifiedAggregateEvidenceStagePackage){
		"runtime material changed": func(stage *VerifiedAggregateEvidenceStagePackage) {
			stage.runtimeMaterialRaw = append(stage.runtimeMaterialRaw, '\n')
		},
		"runtime receipt changed": func(stage *VerifiedAggregateEvidenceStagePackage) {
			stage.runtimeReceiptRaw[0] = 'x'
		},
		"capability changed": func(stage *VerifiedAggregateEvidenceStagePackage) {
			stage.capabilityRaw[0] = 'x'
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := stage
			candidate.runtimeMaterialRaw = append([]byte(nil), stage.runtimeMaterialRaw...)
			candidate.runtimeReceiptRaw = append([]byte(nil), stage.runtimeReceiptRaw...)
			candidate.capabilityRaw = append([]byte(nil), stage.capabilityRaw...)
			mutate(&candidate)
			if _, err := BuildAggregateEvidenceStagePrivateInputPackage(candidate); err == nil {
				t.Fatal("changed private aggregate source was accepted")
			}
		})
	}
	packaged, err := BuildAggregateEvidenceStagePrivateInputPackage(stage)
	if err != nil {
		t.Fatal(err)
	}
	packaged.objects[1].raw = append(packaged.objects[1].raw, '\n')
	if _, err := packaged.Receipt(); err == nil {
		t.Fatal("changed private capability Secret was accepted")
	}
	if _, err := (VerifiedAggregateEvidenceStagePrivateInputPackage{}).Receipt(); err == nil {
		t.Fatal("unverified aggregate private input receipt was exposed")
	}
}
