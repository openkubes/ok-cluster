package runner

import (
	"bytes"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildLifecycleObservationStagePackageBindsMinimalInputAndEnvelope(t *testing.T) {
	config := lifecycleObservationStagePackageConfig(t)
	packaged, err := BuildLifecycleObservationStagePackage(config)
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
	if len(objects) != 3 || objects["ConfigMap"] == nil || objects["NetworkPolicy"] == nil || objects["Job"] == nil {
		t.Fatalf("unexpected lifecycle observation package: %#v", objects)
	}
	configMap := objects["ConfigMap"]
	if configMap["immutable"] != true || objectAt(t, configMap, "metadata")["name"] != config.InputConfigMap {
		t.Fatalf("unexpected observation input ConfigMap: %#v", configMap)
	}
	data := objectAt(t, configMap, "data")
	wantKeys := []string{"lifecycle-receipt.json", "provider-receipt.json", "receipt-prefix.json", "staged-plan.json"}
	gotKeys := make([]string, 0, len(data))
	for key := range data {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) || data["stage-grant.json"] != nil || data["projection-manifest.json"] != nil {
		t.Fatalf("observation input is not minimal: keys=%v", gotKeys)
	}
	job := objects["Job"]
	podSpec := objectAt(t, objectAt(t, objectAt(t, job, "spec"), "template"), "spec")
	container := arrayAt(t, podSpec, "containers")[0].(map[string]any)
	args := stringArray(t, container, "args")
	if argumentValue(args, "--receipt-prefix-digest") != receipt.ReceiptPrefixDigest || argumentValue(args, "--poll-timeout") != "5m0s" {
		t.Fatalf("Job does not bind package inputs: %v %#v", args, receipt)
	}
	if receipt.Format != LifecycleObservationStagePackageFormat || receipt.StageID != "lifecycle-observation" || receipt.PackageDigest != digest.SHA256(raw) || receipt.AuthorizationState != "NOT_REQUIRED" || receipt.MutationAllowed {
		t.Fatalf("unexpected observation package receipt: %#v", receipt)
	}
	parts := bytes.SplitN(raw, []byte("\n---\n"), 2)
	if len(parts) != 2 || receipt.InputConfigMapDigest != digest.SHA256(parts[0]) || receipt.JobEnvelopeDigest != digest.SHA256(parts[1]) {
		t.Fatal("observation package component digests differ")
	}
	if !reflect.DeepEqual(receipt.ObjectKinds, []string{"ConfigMap", "NetworkPolicy", "Job"}) {
		t.Fatalf("unexpected observation package kinds: %v", receipt.ObjectKinds)
	}
	input, err := BuildLifecycleObservationStageInput(config.Bundle, config.InputConfigMap)
	if err != nil {
		t.Fatal(err)
	}
	inputReceipt, _ := input.Receipt()
	if inputReceipt.ConfigMapDigest != receipt.InputConfigMapDigest || inputReceipt.ReceiptPrefixDigest != receipt.ReceiptPrefixDigest || !reflect.DeepEqual(inputReceipt.DataKeys, wantKeys) {
		t.Fatalf("input and package receipts differ: %#v %#v", inputReceipt, receipt)
	}
	raw[0] = 'x'
	again, _ := packaged.Bytes()
	if again[0] != '{' {
		t.Fatal("caller mutated retained observation package")
	}
	receipt.ObjectKinds[0] = "Changed"
	againReceipt, _ := packaged.Receipt()
	if againReceipt.ObjectKinds[0] != "ConfigMap" {
		t.Fatal("caller mutated retained observation package receipt")
	}
}

func TestBuildLifecycleObservationStagePackageFailsClosed(t *testing.T) {
	valid := lifecycleObservationStagePackageConfig(t)
	for name, mutate := range map[string]func(*LifecycleObservationStagePackageConfig){
		"changed template": func(config *LifecycleObservationStagePackageConfig) {
			config.JobTemplate = append(config.JobTemplate, '\n')
		},
		"wrong template digest": func(config *LifecycleObservationStagePackageConfig) { config.JobTemplateDigest = bundleSHA("f") },
		"input reuses ledger secret": func(config *LifecycleObservationStagePackageConfig) {
			config.InputConfigMap = config.LedgerCredentialSecret
		},
		"shared credentials": func(config *LifecycleObservationStagePackageConfig) {
			config.ManagementCredentialSecret = config.LedgerCredentialSecret
		},
		"mutable image": func(config *LifecycleObservationStagePackageConfig) {
			config.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest"
		},
		"foreign endpoint": func(config *LifecycleObservationStagePackageConfig) {
			config.ManagementAPIURL, config.ManagementAPICIDR = "https://192.0.2.13:6443", "192.0.2.13/32"
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			config.JobTemplate = append([]byte(nil), valid.JobTemplate...)
			mutate(&config)
			if _, err := BuildLifecycleObservationStagePackage(config); err == nil {
				t.Fatal("unsafe lifecycle observation package was accepted")
			}
		})
	}
	if _, err := (VerifiedLifecycleObservationStagePackage{}).Bytes(); err == nil {
		t.Fatal("unverified observation package bytes were exposed")
	}
	if _, err := (VerifiedLifecycleObservationStagePackage{}).Receipt(); err == nil {
		t.Fatal("unverified observation package receipt was exposed")
	}
	if _, err := (VerifiedLifecycleObservationStageInput{}).Bytes(); err == nil {
		t.Fatal("unverified observation input bytes were exposed")
	}
}

func lifecycleObservationStagePackageConfig(t *testing.T) LifecycleObservationStagePackageConfig {
	t.Helper()
	values := validLifecycleObservationStageJobValues()
	template := lifecycleObservationJobTemplate(t)
	return LifecycleObservationStagePackageConfig{
		Bundle: lifecycleObservationBundleConfig(t, true), JobTemplate: template, JobTemplateDigest: digest.SHA256(template),
		RunID: values.RunID, ImageDigest: values.ImageDigest, InputConfigMap: values.InputConfigMap,
		LedgerAPIURL: values.LedgerAPIURL, LedgerAPICIDR: values.LedgerAPICIDR, LedgerCredentialSecret: values.LedgerCredentialSecret,
		ManagementAPIURL: values.ManagementAPIURL, ManagementAPICIDR: values.ManagementAPICIDR, ManagementCredentialSecret: values.ManagementCredentialSecret,
		PollInterval: 15 * time.Second, PollTimeout: 5 * time.Minute,
	}
}
