package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildSubmissionStageInputMaterializesExactCredentialFreeConfigMap(t *testing.T) {
	for _, completedProvider := range []bool{false, true} {
		stageID := "provider-prerequisites"
		expectedKeys := []string{
			"authority-map.json", "ok-infra-prerequisites.yaml", "ok-mgmt-lifecycle.yaml",
			"projection-manifest.json", "receipt-prefix.json", "stage-authority.pub",
			"stage-grant.json", "staged-plan.json",
		}
		if completedProvider {
			stageID = "cluster-lifecycle"
			expectedKeys = append(expectedKeys, providerReceiptInputKey)
		}
		sort.Strings(expectedKeys)
		t.Run(stageID, func(t *testing.T) {
			fixture := submissionBundleFixture(t, completedProvider, "")
			verified, err := BuildSubmissionStageInput(fixture.config, "ok147-"+stageID+"-input")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := verified.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := verified.Receipt()
			if err != nil {
				t.Fatal(err)
			}
			var configMap submissionStageInputConfigMap
			if err := json.Unmarshal(raw, &configMap); err != nil {
				t.Fatal(err)
			}
			if configMap.APIVersion != "v1" || configMap.Kind != "ConfigMap" || !configMap.Immutable {
				t.Fatalf("unexpected ConfigMap envelope: %#v", configMap)
			}
			if configMap.Metadata.Name != "ok147-"+stageID+"-input" || configMap.Metadata.Namespace != submissionStageInputNamespace {
				t.Fatalf("unexpected ConfigMap identity: %#v", configMap.Metadata)
			}
			if configMap.Metadata.Labels["openkubes.io/stage-id"] != stageID || configMap.Metadata.Annotations["openkubes.io/input-format"] != SubmissionStageInputFormat {
				t.Fatalf("unexpected ConfigMap binding metadata: %#v", configMap.Metadata)
			}
			if !reflect.DeepEqual(receipt.DataKeys, expectedKeys) {
				t.Fatalf("unexpected input keys: %#v", receipt.DataKeys)
			}
			if len(configMap.Data) != len(expectedKeys) {
				t.Fatalf("unexpected ConfigMap data: %#v", configMap.Data)
			}
			for _, key := range expectedKeys {
				if configMap.Data[key] == "" {
					t.Fatalf("expected non-empty input %s", key)
				}
			}
			for _, forbidden := range []string{"token", "kubeconfig", "private-key", "ca.crt"} {
				for key := range configMap.Data {
					if strings.Contains(strings.ToLower(key), forbidden) {
						t.Fatalf("credential-shaped input key was packaged: %s", key)
					}
				}
			}
			if receipt.Format != SubmissionStageInputFormat || receipt.State != "VERIFIED" || receipt.StageID != stageID || receipt.ConfigMapDigest != digest.SHA256(raw) {
				t.Fatalf("unexpected materialization receipt: %#v", receipt)
			}

			prefixRaw := []byte(configMap.Data["receipt-prefix.json"])
			if receipt.ReceiptPrefixDigest != digest.SHA256(prefixRaw) || configMap.Metadata.Annotations["openkubes.io/receipt-prefix-digest"] != receipt.ReceiptPrefixDigest {
				t.Fatal("receipt-prefix identity is not consistently bound")
			}
			var prefix stageReceiptPrefixDocument
			if err := json.Unmarshal(prefixRaw, &prefix); err != nil {
				t.Fatal(err)
			}
			if prefix.Format != StageReceiptPrefixFormat || prefix.Receipts == nil {
				t.Fatalf("receipt prefix is not explicit: %#v", prefix)
			}
			if completedProvider {
				if len(prefix.Receipts) != 1 || prefix.Receipts[0].File != providerReceiptInputKey || prefix.Receipts[0].Digest != fixture.config.Receipts[0].Digest {
					t.Fatalf("provider receipt was not exactly rebound: %#v", prefix)
				}
				source, err := os.ReadFile(fixture.config.Receipts[0].Path)
				if err != nil {
					t.Fatal(err)
				}
				if configMap.Data[providerReceiptInputKey] != string(source) {
					t.Fatal("packaged provider receipt differs from verified source")
				}
			} else if len(prefix.Receipts) != 0 {
				t.Fatalf("provider stage prefix is not empty: %#v", prefix)
			}

			raw[0] = 'x'
			again, err := verified.Bytes()
			if err != nil || again[0] != '{' {
				t.Fatal("caller mutated retained verified ConfigMap")
			}
			receipt.DataKeys[0] = "changed"
			againReceipt, err := verified.Receipt()
			if err != nil || againReceipt.DataKeys[0] == "changed" {
				t.Fatal("caller mutated retained materialization receipt")
			}
		})
	}
}

func TestBuildSubmissionStageInputFailsClosed(t *testing.T) {
	fixture := submissionBundleFixture(t, false, "")
	if _, err := BuildSubmissionStageInput(fixture.config, "foreign-input"); err == nil {
		t.Fatal("ConfigMap name outside OK-147 boundary was accepted")
	}
	if _, err := BuildSubmissionStageInput(fixture.config, "ok147-"); err == nil {
		t.Fatal("invalid DNS label was accepted")
	}
	if _, err := (VerifiedSubmissionStageInput{}).Bytes(); err == nil {
		t.Fatal("unverified input bytes were exposed")
	}
	if _, err := (VerifiedSubmissionStageInput{}).Receipt(); err == nil {
		t.Fatal("unverified input receipt was exposed")
	}

	fixture = submissionBundleFixture(t, false, "")
	if err := os.WriteFile(fixture.config.GrantPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSubmissionStageInput(fixture.config, "ok147-tampered-input"); err == nil {
		t.Fatal("tampered authorization was packaged")
	}

	fixture = submissionBundleFixture(t, false, "")
	symlink := filepath.Join(t.TempDir(), "projection-manifest.json")
	if err := os.Symlink(fixture.config.ProjectionManifestPath, symlink); err != nil {
		t.Fatal(err)
	}
	fixture.config.ProjectionManifestPath = symlink
	if _, err := BuildSubmissionStageInput(fixture.config, "ok147-symlink-input"); err == nil || !strings.Contains(err.Error(), "bounded submission stage input") {
		t.Fatalf("symlink input was accepted: %v", err)
	}

	fixture = submissionBundleFixture(t, false, "")
	manifest, err := os.ReadFile(fixture.config.ProjectionManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	oversized := append([]byte(strings.Repeat(" ", maximumSubmissionStageInputBytes+1)), manifest...)
	if err := os.WriteFile(fixture.config.ProjectionManifestPath, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSubmissionStageInput(fixture.config, "ok147-oversized-input"); err == nil || !strings.Contains(err.Error(), "bounded submission stage input") {
		t.Fatalf("oversized input was accepted: %v", err)
	}
}
