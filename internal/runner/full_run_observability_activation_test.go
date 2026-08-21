package runner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestOpenKubernetesObservabilityFullRunActivationIsInertAndFullyBound(t *testing.T) {
	manifestPath, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()
	publicKeyPath, keyID := fullRunEvidencePublicKeyFixture(t, filepath.Dir(manifestPath))
	bindFullRunEvidenceKeyID(t, manifestPath, keyID)
	clock := func() time.Time { return time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC) }

	activation, receipt, err := OpenKubernetesObservabilityFullRunActivation(manifestPath, KubernetesObservabilityFullRunActivationConfig{
		IndependentEvidencePublicKeyPath: publicKeyPath, Clock: clock, Wait: WaitWithTimer,
	})
	if err != nil || activation == nil || receipt.Format != FullRunExecutionActivationReceiptFormat || receipt.State != "PREPARED" ||
		receipt.Manifest.State != "VERIFIED" || receipt.Manifest.MutationAllowed || receipt.Execution != nil {
		t.Fatalf("concrete full-run activation did not open inertly: activation=%#v receipt=%#v err=%v", activation, receipt, err)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{filepath.Dir(manifestPath), "token", "endpoint", "kubeconfig", "certificate", "targetidentity"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(forbidden)) {
			t.Fatalf("concrete activation receipt disclosed %q: %s", forbidden, raw)
		}
	}
}

func TestOpenKubernetesObservabilityFullRunActivationRejectsForeignRuntime(t *testing.T) {
	manifestPath, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()
	publicKeyPath, keyID := fullRunEvidencePublicKeyFixture(t, filepath.Dir(manifestPath))
	bindFullRunEvidenceKeyID(t, manifestPath, keyID)
	clock := func() time.Time { return time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC) }
	valid := KubernetesObservabilityFullRunActivationConfig{
		IndependentEvidencePublicKeyPath: publicKeyPath, Clock: clock, Wait: WaitWithTimer,
	}

	for name, mutate := range map[string]func(*KubernetesObservabilityFullRunActivationConfig){
		"missing public key": func(config *KubernetesObservabilityFullRunActivationConfig) {
			config.IndependentEvidencePublicKeyPath = ""
		},
		"missing clock":  func(config *KubernetesObservabilityFullRunActivationConfig) { config.Clock = nil },
		"missing waiter": func(config *KubernetesObservabilityFullRunActivationConfig) { config.Wait = nil },
		"foreign public key": func(config *KubernetesObservabilityFullRunActivationConfig) {
			config.IndependentEvidencePublicKeyPath, _ = fullRunEvidencePublicKeyFixture(t, filepath.Dir(manifestPath))
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			activation, receipt, err := OpenKubernetesObservabilityFullRunActivation(manifestPath, config)
			if err == nil || activation != nil || receipt.State != "STOPPED" || receipt.Execution != nil {
				t.Fatalf("unsafe concrete runtime was accepted: activation=%#v receipt=%#v err=%v", activation, receipt, err)
			}
		})
	}
}

func fullRunEvidencePublicKeyFixture(t *testing.T, root string) (string, string) {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "observability-evidence-"+digest.SHA256(publicKey)[7:15]+".pub")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, digest.SHA256(publicKey)
}

func bindFullRunEvidenceKeyID(t *testing.T, manifestPath, keyID string) {
	t.Helper()
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["platformObservation"].(map[string]any)["capability"].(map[string]any)["independentEvidenceKeyId"] = keyID
	updated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, updated, 0o600); err != nil {
		t.Fatal(err)
	}
}
