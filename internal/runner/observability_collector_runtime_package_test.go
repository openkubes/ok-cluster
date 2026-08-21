package runner

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildObservabilityCollectorRuntimePackageBindsFourObjects(t *testing.T) {
	config := observabilityCollectorRuntimePackageFixture(t)
	packaged, err := BuildObservabilityCollectorRuntimePackage(config)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := packaged.PrivateBytes()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != ObservabilityCollectorRuntimePackageFormat || receipt.State != "VERIFIED" ||
		receipt.PackageDigest != digest.SHA256(raw) || receipt.ImageDigest != config.ImageDigest || receipt.MutationAllowed ||
		!reflect.DeepEqual(receipt.ObjectKinds, []string{"Secret", "Service", "NetworkPolicy", "Job"}) {
		t.Fatalf("unexpected collector runtime receipt: %#v", receipt)
	}
	parts := bytes.Split(raw, []byte("\n---\n"))
	if len(parts) != 4 || digest.SHA256(parts[0]) != receipt.ActivationObjectDigest ||
		digest.SHA256(parts[1]) != receipt.ServiceObjectDigest || digest.SHA256(parts[2]) != receipt.NetworkPolicyObjectDigest ||
		digest.SHA256(parts[3]) != receipt.JobObjectDigest {
		t.Fatal("collector runtime package object identity differs")
	}
	receipt.ObjectKinds[0] = "Changed"
	again, err := packaged.Receipt()
	if err != nil || again.ObjectKinds[0] != "Secret" {
		t.Fatal("caller mutated retained collector runtime receipt")
	}
}

func TestBuildObservabilityCollectorRuntimePackageFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*ObservabilityCollectorRuntimePackageConfig){
		"wrong template": func(config *ObservabilityCollectorRuntimePackageConfig) {
			config.JobTemplateDigest = runnerStageSHA("f")
		},
		"mutable image": func(config *ObservabilityCollectorRuntimePackageConfig) {
			config.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest"
		},
		"broad alert source": func(config *ObservabilityCollectorRuntimePackageConfig) { config.AlertSourceCIDR = "0.0.0.0/0" },
	} {
		t.Run(name, func(t *testing.T) {
			config := observabilityCollectorRuntimePackageFixture(t)
			mutate(&config)
			if packaged, err := BuildObservabilityCollectorRuntimePackage(config); err == nil || packaged.verified {
				t.Fatal("unsafe collector runtime package was accepted")
			}
		})
	}
	if _, err := (VerifiedObservabilityCollectorRuntimePackage{}).PrivateBytes(); err == nil {
		t.Fatal("unverified collector runtime bytes were exposed")
	}
}

func observabilityCollectorRuntimePackageFixture(t *testing.T) ObservabilityCollectorRuntimePackageConfig {
	t.Helper()
	activation, cleanup := observabilityCollectorActivationFixture(t)
	t.Cleanup(cleanup)
	template := observabilityCollectorJobTemplate(t)
	return ObservabilityCollectorRuntimePackageConfig{
		Activation: activation, JobTemplate: template, JobTemplateDigest: digest.SHA256(template),
		RunID: "ok147-evidence-collector-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@" + runnerStageSHA("a"),
		WorkloadAPICIDR: "192.0.2.147/32", AlertSourceCIDR: "10.244.0.0/16",
	}
}
