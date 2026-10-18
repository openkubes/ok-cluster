package runner

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/openkubes/ok-cluster/internal/kubeconfigtarget"
)

func TestFullRunPlaneTargetsMustMatchAuthoritiesAndProviderAccess(t *testing.T) {
	path, cleanup := fullRunExecutionManifestFixture(t)
	defer cleanup()
	doc, _ := readFullRunExecutionFixture(t, path)
	config := func(authority postRuntimeAuthorityDocument) []byte {
		ca, err := os.ReadFile(authority.CAFile)
		if err != nil {
			t.Fatal(err)
		}
		return []byte(fmt.Sprintf("apiVersion: v1\nkind: Config\ncurrent-context: only\ncontexts:\n- name: only\n  context: {cluster: selected, user: operator}\nclusters:\n- name: selected\n  cluster:\n    server: %s\n    certificate-authority-data: %s\nusers:\n- name: operator\n  user: {token: offline-provider-access-only}\n", authority.Endpoint, base64.StdEncoding.EncodeToString(ca)))
	}
	if err := os.WriteFile(doc.ProviderAccess.KubeconfigFile, config(doc.ProviderPrerequisites.Authority), 0o600); err != nil {
		t.Fatal(err)
	}
	selectTarget := func(name string, authority postRuntimeAuthorityDocument) kubeconfigtarget.Target {
		file := filepath.Join(t.TempDir(), name+".yaml")
		if err := os.WriteFile(file, config(authority), 0o600); err != nil {
			t.Fatal(err)
		}
		target, err := kubeconfigtarget.Read(file, "")
		if err != nil {
			t.Fatal(err)
		}
		return target
	}
	mgmt := selectTarget("mgmt", doc.ClusterLifecycle.Authority)
	infra := selectTarget("infra", doc.ProviderPrerequisites.Authority)
	_, receipt, err := LoadFullRunExecutionManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFullRunManifestPlaneTargets(path, receipt.ManifestDigest, mgmt, infra); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFullRunManifestPlaneTargets(path, receipt.ManifestDigest, infra, mgmt); err == nil {
		t.Fatal("swapped planes accepted")
	}
	if err := VerifyFullRunManifestPlaneTargets(path, "wrong digest", mgmt, infra); err == nil {
		t.Fatal("unbound manifest accepted")
	}
	foreign := mgmt
	foreign.CATrustDigest = "different-trust"
	if err := VerifyFullRunManifestPlaneTargets(path, receipt.ManifestDigest, foreign, infra); err == nil {
		t.Fatal("foreign CA accepted")
	}
	if err := os.WriteFile(doc.ProviderAccess.KubeconfigFile, config(doc.ClusterLifecycle.Authority), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFullRunManifestPlaneTargets(path, receipt.ManifestDigest, mgmt, infra); err == nil {
		t.Fatal("provider-access pointed at management")
	}
}
