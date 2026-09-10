package runner

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestClassifyObservabilityCollectorActivationPackageBuildStop(t *testing.T) {
	tests := []struct {
		detail   string
		category string
	}{
		{"observability collector activation identity is invalid", "POST_PREFIX_ACTIVATION_IDENTITY_INVALID"},
		{"observability collector manifest receipt is invalid", "POST_PREFIX_ACTIVATION_MANIFEST_BINDING_INVALID"},
		{"observability collector runtime binding differs from manifest", "POST_PREFIX_ACTIVATION_RUNTIME_BINDING_INVALID"},
		{"verify observability collector observer credential", "POST_PREFIX_ACTIVATION_OBSERVER_CREDENTIAL_INVALID"},
		{"observability collector workload CA differs from runtime binding", "POST_PREFIX_ACTIVATION_WORKLOAD_CA_INVALID"},
		{"observability collector authorities must be distinct", "POST_PREFIX_ACTIVATION_AUTHORITIES_INVALID"},
		{"observability collector TLS certificate is invalid", "POST_PREFIX_ACTIVATION_TLS_NETWORK_INVALID"},
		{"observability collector record age is invalid", "POST_PREFIX_ACTIVATION_POLICY_OR_SIZE_INVALID"},
		{"private detail that must not define a category", "POST_PREFIX_ACTIVATION_PACKAGE_BUILD_STOPPED"},
	}
	for _, test := range tests {
		t.Run(test.category, func(t *testing.T) {
			err := classifyObservabilityCollectorActivationPackageBuildStop(errors.New(test.detail))
			if got := redactedStopCategory(err); got != test.category {
				t.Fatalf("unexpected category: got %s want %s", got, test.category)
			}
			if got := redactedStopCategory(err); strings.Contains(got, "private") || !validPostPrefixPackageConstructionStopCategory(got) || !validRedactedStopCategory(got) {
				t.Fatalf("category is not safely propagated: %q", got)
			}
		})
	}
}

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
	activationPackage, err := BuildObservabilityCollectorActivationPackage(config.Activation)
	if err != nil {
		t.Fatal(err)
	}
	activationReceipt, err := activationPackage.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != ObservabilityCollectorRuntimePackageFormat || receipt.State != "VERIFIED" ||
		receipt.PackageDigest != digest.SHA256(raw) || receipt.ImageDigest != config.ImageDigest || receipt.MutationAllowed ||
		receipt.TLSCertificateDigest != activationReceipt.TLSCertificateDigest ||
		receipt.ReceiverIdentityDigest != activationReceipt.ReceiverIdentityDigest || receipt.ProfileDigest != activationReceipt.ProfileDigest ||
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
