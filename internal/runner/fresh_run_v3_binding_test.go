package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBindFreshRunV3CorrelatesPublicationExecutorAndCollector(t *testing.T) {
	config := freshRunV3BindingFixture(t)
	receipt, err := BindFreshRunV3(config)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != "VERIFIED_NOT_AUTHORIZED" || receipt.MutationAllowed ||
		receipt.ImageDigest != boundedRunnerImage+"@"+runnerStageSHA("1") ||
		receipt.SourceManifestDigest != runnerStageSHA("b") || receipt.CollectorEndpointDigest != runnerStageSHA("e") ||
		receipt.CollectorTLSCertificateDigest != runnerStageSHA("f") || verifyFreshRunV3BindingReceipt(receipt) != nil {
		t.Fatalf("unexpected fresh-run v3 binding: %#v", receipt)
	}
}

func TestBindFreshRunV3FailsClosedOnCrossReceiptDrift(t *testing.T) {
	tests := map[string]func(*FreshRunV3BindingConfig){
		"source": func(config *FreshRunV3BindingConfig) { config.ExpectedSourceSHA = strings.Repeat("9", 40) },
		"publication receipt": func(config *FreshRunV3BindingConfig) {
			config.ExpectedPublicationReceiptDigest = runnerStageSHA("9")
		},
		"executor receipt": func(config *FreshRunV3BindingConfig) {
			config.ExpectedFullRunPackageDigest = runnerStageSHA("9")
		},
		"collector receipt": func(config *FreshRunV3BindingConfig) {
			config.ExpectedCollectorPackageDigest = runnerStageSHA("9")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := freshRunV3BindingFixture(t)
			mutate(&config)
			if _, err := BindFreshRunV3(config); err == nil {
				t.Fatal("drifted fresh-run receipt set was accepted")
			}
		})
	}
}

func TestBindFreshRunV3RejectsDifferentReceiverIdentity(t *testing.T) {
	config := freshRunV3BindingFixture(t)
	raw, err := os.ReadFile(config.CollectorPackageReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var collector ObservabilityCollectorRuntimePackageReceipt
	if err := json.Unmarshal(raw, &collector); err != nil {
		t.Fatal(err)
	}
	collector.PublicEndpointDigest = runnerStageSHA("9")
	config.ExpectedCollectorPackageDigest = writeFreshRunReceipt(t, config.CollectorPackageReceiptPath, collector)
	if _, err := BindFreshRunV3(config); err == nil {
		t.Fatal("collector with a foreign receiver endpoint was accepted")
	}
}

func freshRunV3BindingFixture(t *testing.T) FreshRunV3BindingConfig {
	t.Helper()
	root := t.TempDir()
	source := strings.Repeat("1", 40)
	imageDigest := runnerStageSHA("1")
	platforms := map[string]string{"linux/amd64": runnerStageSHA("2"), "linux/arm64": runnerStageSHA("3")}
	publication := freshRunPublicationReceipt{
		Format: runnerPublicationReceiptFormat, Image: boundedRunnerImage, Digest: imageDigest, SourceSHA: source,
		Version: "0.1.0-dev", PublicationContractDigest: runnerStageSHA("4"),
		WorkflowRunURL:          "https://github.com/openkubes/ok-cluster/actions/runs/12345",
		PlatformManifestDigests: platforms,
		Attestations: map[string]freshRunPublicationAttestation{
			platforms["linux/amd64"]: {ManifestDigest: runnerStageSHA("5"), PredicateTypes: []string{"https://slsa.dev/provenance/v1", "https://spdx.dev/Document"}},
			platforms["linux/arm64"]: {ManifestDigest: runnerStageSHA("6"), PredicateTypes: []string{"https://spdx.dev/Document", "https://slsa.dev/provenance/v1"}},
		},
		GitHubAttestationVerificationDigest: runnerStageSHA("7"), PullbackByDigestVerified: true,
		NetworkPublicationPerformed: true, DeploymentPerformed: false, ClusterContactPerformed: false,
	}
	fullRun := FullRunExecutionActivationPackageReceipt{
		Format: FullRunExecutionActivationPackageFormat, State: "VERIFIED", PackageDigest: runnerStageSHA("8"),
		SourceManifestDigest: runnerStageSHA("b"), ManifestDigest: runnerStageSHA("c"), PlanDigest: runnerStageSHA("d"),
		EvidenceActivationDigest: runnerStageSHA("a"), EvidenceKeyID: runnerStageSHA("0"),
		CollectorAuthorityDigest: runnerStageSHA("e"), CollectorCADigest: runnerStageSHA("f"),
		ImageDigest: boundedRunnerImage + "@" + imageDigest,
		ObjectKinds: []string{"Secret", "Secret", "NetworkPolicy", "Job"}, MutationAllowed: false,
	}
	collector := ObservabilityCollectorRuntimePackageReceipt{
		Format: ObservabilityCollectorRuntimePackageFormat, State: "VERIFIED", PackageDigest: runnerStageSHA("1"),
		ManifestDigest: runnerStageSHA("b"), RuntimeBindingDigest: runnerStageSHA("2"),
		PublicEndpointDigest: runnerStageSHA("e"), TLSCertificateDigest: runnerStageSHA("f"),
		ReceiverIdentityDigest: runnerStageSHA("3"), ProfileDigest: runnerStageSHA("4"),
		ImageDigest: boundedRunnerImage + "@" + imageDigest,
		ObjectKinds: []string{"Secret", "Service", "NetworkPolicy", "Job"}, MutationAllowed: false,
	}
	publicationPath := filepath.Join(root, "publication.json")
	fullRunPath := filepath.Join(root, "full-run.json")
	collectorPath := filepath.Join(root, "collector.json")
	return FreshRunV3BindingConfig{
		PublicationReceiptPath: publicationPath, ExpectedPublicationReceiptDigest: writeFreshRunReceipt(t, publicationPath, publication), ExpectedSourceSHA: source,
		FullRunPackageReceiptPath: fullRunPath, ExpectedFullRunPackageDigest: writeFreshRunReceipt(t, fullRunPath, fullRun),
		CollectorPackageReceiptPath: collectorPath, ExpectedCollectorPackageDigest: writeFreshRunReceipt(t, collectorPath, collector),
	}
}

func writeFreshRunReceipt(t *testing.T, path string, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return digest.SHA256(raw)
}
