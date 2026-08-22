package runner

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildFullRunExecutionActivationPackageBindsBothAuthoritiesAndJob(t *testing.T) {
	config := fullRunExecutionActivationPackageFixture(t)
	packaged, err := BuildFullRunExecutionActivationPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil || receipt.State != "VERIFIED" || receipt.MutationAllowed ||
		receipt.PrivateFileCount != len(fullRunExecutionBundleFiles)+len(observabilityEvidenceAuthorityProjectedFiles) ||
		receipt.ActivationSecret != config.ActivationSecret || receipt.EvidenceAuthoritySecret != config.EvidenceAuthority.ActivationSecret ||
		receipt.ManagementAuthority != "ok-mgmt" || receipt.ImageDigest != config.Job.ImageDigest || len(receipt.ObjectKinds) != 4 {
		t.Fatalf("unexpected full-run package receipt: %#v err=%v", receipt, err)
	}
	raw, err := packaged.PrivateBytes()
	if err != nil || digest.SHA256(raw) != receipt.PackageDigest {
		t.Fatalf("private full-run package differs: %v", err)
	}
	parts := bytes.SplitN(raw, []byte("\n---\n"), 3)
	if len(parts) != 3 {
		t.Fatalf("unexpected package component count: %d", len(parts))
	}
	for index, part := range parts[:2] {
		var object map[string]any
		if err := json.Unmarshal(part, &object); err != nil {
			t.Fatal(err)
		}
		if object["data"] == nil || object["binaryData"] != nil {
			t.Fatalf("Kubernetes Secret %d must use data and never binaryData", index)
		}
	}
	var activationSecret, evidenceSecret postRuntimeActivationSecret
	if err := json.Unmarshal(parts[0], &activationSecret); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(parts[1], &evidenceSecret); err != nil {
		t.Fatal(err)
	}
	if !activationSecret.Immutable || len(activationSecret.Data) != len(fullRunExecutionBundleFiles)+1 ||
		!evidenceSecret.Immutable || len(evidenceSecret.Data) != 4 ||
		activationSecret.Metadata.Name == evidenceSecret.Metadata.Name {
		t.Fatalf("private Secret boundary differs: activation=%#v evidence=%#v", activationSecret.Metadata, evidenceSecret.Metadata)
	}
	objects := decodeJobObjects(t, parts[2])
	if objects["NetworkPolicy"] == nil || objects["Job"] == nil {
		t.Fatalf("bounded Job envelope differs: %#v", objects)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{filepath.Dir(config.ManifestPath), config.EvidenceAuthority.CollectorEndpoint, "token", "kubeconfig", "private-key", "BEGIN CERTIFICATE"} {
		if strings.Contains(strings.ToLower(string(public)), strings.ToLower(forbidden)) {
			t.Fatalf("public full-run package receipt disclosed %q: %s", forbidden, public)
		}
	}
}

func TestBuildFullRunExecutionActivationPackageFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*FullRunExecutionActivationPackageConfig){
		"wrong template": func(config *FullRunExecutionActivationPackageConfig) { config.JobTemplateDigest = bundleSHA("f") },
		"same Secret": func(config *FullRunExecutionActivationPackageConfig) {
			config.ActivationSecret = config.EvidenceAuthority.ActivationSecret
		},
		"mutable image": func(config *FullRunExecutionActivationPackageConfig) {
			config.Job.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest"
		},
		"broad workload CIDR": func(config *FullRunExecutionActivationPackageConfig) { config.Job.WorkloadAPICIDR = "192.0.2.0/24" },
		"foreign evidence key": func(config *FullRunExecutionActivationPackageConfig) {
			config.IndependentEvidencePublicKey = config.EvidenceAuthority.CollectorCAPath
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := fullRunExecutionActivationPackageFixture(t)
			mutate(&config)
			if packaged, err := BuildFullRunExecutionActivationPackage(config); err == nil || packaged.verified {
				t.Fatalf("unsafe full-run activation package was accepted: %#v err=%v", packaged.receipt, err)
			}
		})
	}
}

func TestFullRunExecutionActivationPackageRejectsTampering(t *testing.T) {
	config := fullRunExecutionActivationPackageFixture(t)
	packaged, err := BuildFullRunExecutionActivationPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.raw[0] ^= 0xff
	if _, err := packaged.PrivateBytes(); err == nil {
		t.Fatal("tampered full-run package bytes were accepted")
	}
	packaged, err = BuildFullRunExecutionActivationPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.receipt.ObjectKinds[1] = "ConfigMap"
	if _, err := packaged.Receipt(); err == nil {
		t.Fatal("tampered full-run package inventory was accepted")
	}
}

func fullRunExecutionActivationPackageFixture(t *testing.T) FullRunExecutionActivationPackageConfig {
	t.Helper()
	evidenceConfig, cleanup := observabilityEvidenceAuthorityPackageFixture(t)
	t.Cleanup(cleanup)
	privateRaw, err := os.ReadFile(evidenceConfig.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(string(privateRaw), "\n"))
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		t.Fatal("invalid fixture private key")
	}
	publicPath := filepath.Join(t.TempDir(), "evidence-authority.pub")
	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	if err := os.WriteFile(publicPath, []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	template := fullRunExecutionJobTemplate(t)
	return FullRunExecutionActivationPackageConfig{
		ManifestPath: evidenceConfig.ManifestPath, IndependentEvidencePublicKey: publicPath,
		ActivationSecret: "ok147-full-run-activation-01", EvidenceAuthority: evidenceConfig,
		JobTemplate: template, JobTemplateDigest: digest.SHA256(template),
		Job: FullRunExecutionJobValues{
			RunID: "ok147-full-run-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@" + bundleSHA("a"),
			InfrastructureAPICIDR: "192.0.2.13/32", ManagementAPICIDR: "192.0.2.12/32",
			WorkloadAPIURL: "https://192.0.2.30:6443", WorkloadAPICIDR: "192.0.2.30/32",
			ArgoAPICIDR: "192.0.2.11/32", AuthorizationAPICIDR: "127.0.0.1/32",
			CollectorAPICIDR: collectorFixtureCIDR(t, evidenceConfig.CollectorEndpoint),
		},
	}
}

func collectorFixtureCIDR(t *testing.T, endpoint string) string {
	t.Helper()
	// httptest.NewTLSServer always binds an IPv4 loopback endpoint in this
	// fixture; the URL parser in the renderer verifies the exact match.
	if !strings.HasPrefix(endpoint, "https://127.0.0.1:") {
		t.Fatalf("unexpected fixture collector endpoint: %s", endpoint)
	}
	return "127.0.0.1/32"
}
