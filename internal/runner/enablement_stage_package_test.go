package runner

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildEnablementStagePackageBindsInputAndJobEnvelope(t *testing.T) {
	fixture := enablementBundleFixture(t)
	config := enablementStagePackageConfig(t, fixture)
	packaged, err := BuildEnablementStagePackage(config)
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
		t.Fatalf("unexpected enablement package object set: %#v", objects)
	}
	configMap := objects["ConfigMap"]
	if configMap["immutable"] != true || objectAt(t, configMap, "metadata")["name"] != config.InputConfigMap {
		t.Fatalf("unexpected enablement input ConfigMap: %#v", configMap)
	}
	job := objects["Job"]
	container := arrayAt(t, objectAt(t, objectAt(t, objectAt(t, job, "spec"), "template"), "spec"), "containers")[0].(map[string]any)
	args := stringArray(t, container, "args")
	if argumentValue(args, "--helmchartproxy-name") != config.HelmChartProxyName || argumentValue(args, "--evaluation-time") != fixture.config.EvaluationTime.UTC().Format("2006-01-02T15:04:05Z07:00") {
		t.Fatalf("enablement Job and package bindings differ: %v %#v", args, receipt)
	}
	if receipt.Format != EnablementStagePackageFormat || receipt.State != "VERIFIED" || receipt.StageID != "enablement" || receipt.PackageDigest != digest.SHA256(raw) || receipt.MutationAllowed {
		t.Fatalf("unexpected enablement package receipt: %#v", receipt)
	}
	parts := bytes.SplitN(raw, []byte("\n---\n"), 2)
	if len(parts) != 2 || receipt.InputConfigMapDigest != digest.SHA256(parts[0]) || receipt.JobEnvelopeDigest != digest.SHA256(parts[1]) {
		t.Fatal("enablement package component digests do not match emitted bytes")
	}
	if receipt.JobTemplateDigest != digest.SHA256(config.JobTemplate) || receipt.EnablementDigest == "" || !reflect.DeepEqual(receipt.ObjectKinds, []string{"ConfigMap", "NetworkPolicy", "Job"}) {
		t.Fatalf("enablement package identities differ: %#v", receipt)
	}
	policyPosition := bytes.Index(raw, []byte("\nkind: NetworkPolicy\n"))
	jobPosition := bytes.Index(raw, []byte("\nkind: Job\n"))
	if policyPosition < 0 || jobPosition < 0 || policyPosition >= jobPosition {
		t.Fatal("enablement executable Job appears before its NetworkPolicy boundary")
	}

	raw[0] = 'x'
	again, err := packaged.Bytes()
	if err != nil || again[0] != '{' {
		t.Fatal("caller mutated retained enablement package")
	}
	receipt.ObjectKinds[0] = "Changed"
	againReceipt, err := packaged.Receipt()
	if err != nil || againReceipt.ObjectKinds[0] != "ConfigMap" {
		t.Fatal("caller mutated retained enablement package receipt")
	}
}

func TestBuildEnablementStagePackageFailsClosed(t *testing.T) {
	fixture := enablementBundleFixture(t)
	valid := enablementStagePackageConfig(t, fixture)
	for name, mutate := range map[string]func(*EnablementStagePackageConfig){
		"input reuses ledger Secret":     func(config *EnablementStagePackageConfig) { config.InputConfigMap = config.LedgerCredentialSecret },
		"input reuses management Secret": func(config *EnablementStagePackageConfig) { config.InputConfigMap = config.ManagementCredentialSecret },
		"mutable image":                  func(config *EnablementStagePackageConfig) { config.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest" },
		"foreign endpoint":               func(config *EnablementStagePackageConfig) { config.ManagementAPIURL = "https://192.0.2.13:6443" },
		"changed template": func(config *EnablementStagePackageConfig) {
			config.JobTemplate = append(config.JobTemplate, []byte("\n${UNKNOWN}")...)
		},
		"wrong template digest": func(config *EnablementStagePackageConfig) { config.JobTemplateDigest = prefixSHA("f") },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			config.JobTemplate = append([]byte(nil), valid.JobTemplate...)
			mutate(&config)
			if _, err := BuildEnablementStagePackage(config); err == nil {
				t.Fatal("incoherent enablement stage package was accepted")
			}
		})
	}
	if _, err := (VerifiedEnablementStagePackage{}).Bytes(); err == nil {
		t.Fatal("unverified enablement package bytes were exposed")
	}
	if _, err := (VerifiedEnablementStagePackage{}).Receipt(); err == nil {
		t.Fatal("unverified enablement package receipt was exposed")
	}
}

func enablementStagePackageConfig(t *testing.T, fixture enablementBundleTestFixture) EnablementStagePackageConfig {
	t.Helper()
	values := validEnablementStageJobValues()
	config := EnablementStagePackageConfig{
		Bundle: fixture.config, JobTemplate: enablementStageJobTemplate(t),
		RunID: values.RunID, ImageDigest: values.ImageDigest, InputConfigMap: values.InputConfigMap, HelmChartProxyName: values.HelmChartProxyName,
		LedgerAPIURL: values.LedgerAPIURL, LedgerAPICIDR: values.LedgerAPICIDR, LedgerCredentialSecret: values.LedgerCredentialSecret,
		ManagementAPIURL: values.ManagementAPIURL, ManagementAPICIDR: values.ManagementAPICIDR, ManagementCredentialSecret: values.ManagementCredentialSecret,
	}
	config.JobTemplateDigest = digest.SHA256(config.JobTemplate)
	return config
}
