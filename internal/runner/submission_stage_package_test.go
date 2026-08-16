package runner

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildSubmissionStagePackageBindsInputAndJobEnvelope(t *testing.T) {
	for _, completedProvider := range []bool{false, true} {
		stageID := "provider-prerequisites"
		if completedProvider {
			stageID = "cluster-lifecycle"
		}
		t.Run(stageID, func(t *testing.T) {
			fixture := submissionBundleFixture(t, completedProvider, "")
			config := submissionStagePackageConfig(t, fixture, stageID)
			packaged, err := BuildSubmissionStagePackage(config)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := packaged.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := packaged.Receipt()
			if err != nil {
				t.Fatal(err)
			}
			objects := decodeJobObjects(t, raw)
			if len(objects) != 3 || objects["ConfigMap"] == nil || objects["Job"] == nil || objects["NetworkPolicy"] == nil {
				t.Fatalf("unexpected package object set: %#v", objects)
			}
			configMap := objects["ConfigMap"]
			if configMap["immutable"] != true || objectAt(t, configMap, "metadata")["name"] != config.InputConfigMap {
				t.Fatalf("unexpected input ConfigMap: %#v", configMap)
			}
			job := objects["Job"]
			podSpec := objectAt(t, objectAt(t, objectAt(t, job, "spec"), "template"), "spec")
			container := arrayAt(t, podSpec, "containers")[0].(map[string]any)
			args := stringArray(t, container, "args")
			if argumentValue(args, "--expected-stage") != stageID || argumentValue(args, "--receipt-prefix-digest") != receipt.ReceiptPrefixDigest {
				t.Fatalf("Job and package bindings differ: %v %#v", args, receipt)
			}
			if argumentValue(args, "--evaluation-time") != fixture.config.EvaluationTime.UTC().Format("2006-01-02T15:04:05Z07:00") {
				t.Fatal("Job evaluation time was not derived from the verified bundle")
			}
			if receipt.Format != SubmissionStagePackageFormat || receipt.State != "VERIFIED" || receipt.StageID != stageID || receipt.PackageDigest != digest.SHA256(raw) || receipt.MutationAllowed {
				t.Fatalf("unexpected package receipt: %#v", receipt)
			}
			parts := bytes.SplitN(raw, []byte("\n---\n"), 2)
			if len(parts) != 2 || receipt.InputConfigMapDigest != digest.SHA256(parts[0]) || receipt.JobEnvelopeDigest != digest.SHA256(parts[1]) {
				t.Fatal("package component digests do not match exact emitted bytes")
			}
			if !reflect.DeepEqual(receipt.ObjectKinds, []string{"ConfigMap", "Job", "NetworkPolicy"}) || receipt.AuthorizationState != "VERIFIED" {
				t.Fatalf("unexpected package object/authorization state: %#v", receipt)
			}
			input, err := BuildSubmissionStageInput(fixture.config, config.InputConfigMap)
			if err != nil {
				t.Fatal(err)
			}
			inputReceipt, err := input.Receipt()
			if err != nil {
				t.Fatal(err)
			}
			if receipt.InputConfigMapDigest != inputReceipt.ConfigMapDigest || receipt.ReceiptPrefixDigest != inputReceipt.ReceiptPrefixDigest {
				t.Fatal("package does not bind the independently verified input")
			}

			raw[0] = 'x'
			again, err := packaged.Bytes()
			if err != nil || again[0] != '{' {
				t.Fatal("caller mutated retained package")
			}
			receipt.ObjectKinds[0] = "Changed"
			againReceipt, err := packaged.Receipt()
			if err != nil || againReceipt.ObjectKinds[0] != "ConfigMap" {
				t.Fatal("caller mutated retained package receipt")
			}
		})
	}
}

func TestBuildSubmissionStagePackageFailsClosed(t *testing.T) {
	fixture := submissionBundleFixture(t, false, "")
	valid := submissionStagePackageConfig(t, fixture, "provider-prerequisites")
	for name, mutate := range map[string]func(*SubmissionStagePackageConfig){
		"input reuses ledger Secret": func(config *SubmissionStagePackageConfig) {
			config.InputConfigMap = config.LedgerCredentialSecret
		},
		"input reuses authority Secret": func(config *SubmissionStagePackageConfig) {
			config.InputConfigMap = config.AuthorityCredentialSecret
		},
		"mutable image": func(config *SubmissionStagePackageConfig) {
			config.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest"
		},
		"foreign provider endpoint": func(config *SubmissionStagePackageConfig) {
			config.AuthorityAPIURL, config.AuthorityAPICIDR = config.LedgerAPIURL, config.LedgerAPICIDR
		},
		"changed template": func(config *SubmissionStagePackageConfig) {
			config.JobTemplate = append(config.JobTemplate, []byte("\n${UNKNOWN}")...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			config.JobTemplate = append([]byte(nil), valid.JobTemplate...)
			mutate(&config)
			if _, err := BuildSubmissionStagePackage(config); err == nil {
				t.Fatal("incoherent submission stage package was accepted")
			}
		})
	}
	if _, err := (VerifiedSubmissionStagePackage{}).Bytes(); err == nil {
		t.Fatal("unverified package bytes were exposed")
	}
	if _, err := (VerifiedSubmissionStagePackage{}).Receipt(); err == nil {
		t.Fatal("unverified package receipt was exposed")
	}
}

func submissionStagePackageConfig(t *testing.T, fixture submissionBundleTestFixture, stageID string) SubmissionStagePackageConfig {
	t.Helper()
	values := validSubmissionStageJobValues()
	values.StageID = stageID
	if stageID == "cluster-lifecycle" {
		values.AuthorityAPIURL, values.AuthorityAPICIDR = values.LedgerAPIURL, values.LedgerAPICIDR
	}
	return SubmissionStagePackageConfig{
		Bundle: fixture.config, JobTemplate: submissionStageJobTemplate(t),
		RunID: values.RunID, ImageDigest: values.ImageDigest, InputConfigMap: values.InputConfigMap,
		LedgerAPIURL: values.LedgerAPIURL, LedgerAPICIDR: values.LedgerAPICIDR, LedgerCredentialSecret: values.LedgerCredentialSecret,
		AuthorityAPIURL: values.AuthorityAPIURL, AuthorityAPICIDR: values.AuthorityAPICIDR, AuthorityCredentialSecret: values.AuthorityCredentialSecret,
	}
}

func argumentValue(arguments []string, name string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	return ""
}
